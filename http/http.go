package http

import (
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"os"
	"os/signal"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"syscall"
	"time"

	"github.com/gofiber/fiber/v2"
	"github.com/gofiber/fiber/v2/middleware/compress"
	"github.com/gofiber/fiber/v2/middleware/cors"
	"github.com/gofiber/fiber/v2/middleware/limiter"
	"github.com/gofiber/fiber/v2/middleware/recover"
	"github.com/oschwald/geoip2-golang"
	"github.com/yoruakio/gowebserver/config"
	"github.com/yoruakio/gowebserver/logger"
)

type cacheEntry struct {
	value     interface{}
	expiresAt time.Time
}

type connectionTracker struct {
	count      int
	timestamps []time.Time
	mutex      sync.Mutex
}

var (
	ipBlacklist   sync.Map
	proxyCache    sync.Map
	connectionMap sync.Map
	httpClient    = &http.Client{
		Timeout: 5 * time.Second,
		Transport: &http.Transport{
			MaxIdleConns:        100,
			MaxIdleConnsPerHost: 10,
			IdleConnTimeout:     90 * time.Second,
		},
	}
	circuitBreakerFailures uint64
	circuitBreakerOpen     bool
	circuitBreakerMutex    sync.RWMutex
	contentTypes           = map[string]string{
		".ico":  "image/x-icon",
		".html": "text/html",
		".js":   "text/javascript",
		".json": "application/json",
		".css":  "text/css",
		".png":  "image/png",
		".jpg":  "image/jpeg",
		".wav":  "audio/wav",
		".mp3":  "audio/mpeg",
		".svg":  "image/svg+xml",
		".pdf":  "application/pdf",
		".doc":  "application/msword",
	}
)

const geoLite2URL = "https://codeberg.org/Vo/GOWebServer-Depedencies/raw/branch/main/GeoLite2-City.mmdb"

// @note progress writer for tracking download progress
type progressWriter struct {
	total      int64
	downloaded int64
	startTime  time.Time
	lastUpdate time.Time
}

func (pw *progressWriter) Write(p []byte) (int, error) {
	n := len(p)
	pw.downloaded += int64(n)

	now := time.Now()
	if now.Sub(pw.lastUpdate) >= 500*time.Millisecond || pw.downloaded == pw.total {
		elapsed := now.Sub(pw.startTime).Seconds()
		speed := float64(pw.downloaded) / elapsed / 1024 / 1024
		progress := float64(pw.downloaded) / float64(pw.total) * 100

		downloadedMB := float64(pw.downloaded) / 1024 / 1024
		totalMB := float64(pw.total) / 1024 / 1024

		logger.Infof("Downloading: %.2f/%.2f MB (%.1f%%) - %.2f MB/s",
			downloadedMB, totalMB, progress, speed)

		pw.lastUpdate = now
	}

	return n, nil
}

// @note download GeoLite2 database from remote repository
func downloadGeoLite2DB(filepath string) error {
	dir := "mmdb/GOWebServer-Depedencies"
	if err := os.MkdirAll(dir, 0755); err != nil {
		return fmt.Errorf("failed to create directory: %w", err)
	}

	client := &http.Client{
		Timeout: 120 * time.Second,
	}

	resp, err := client.Get(geoLite2URL)
	if err != nil {
		return fmt.Errorf("failed to download: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("download failed with status: %d", resp.StatusCode)
	}

	out, err := os.Create(filepath)
	if err != nil {
		return fmt.Errorf("failed to create file: %w", err)
	}
	defer out.Close()

	pw := &progressWriter{
		total:      resp.ContentLength,
		startTime:  time.Now(),
		lastUpdate: time.Now(),
	}

	writer := io.MultiWriter(out, pw)

	if _, err := io.Copy(writer, resp.Body); err != nil {
		return fmt.Errorf("failed to write file: %w", err)
	}

	return nil
}

type IPAPIResponse struct {
	Query       string  `json:"query"`
	Status      string  `json:"status"`
	Country     string  `json:"country"`
	CountryCode string  `json:"countryCode"`
	Region      string  `json:"region"`
	RegionName  string  `json:"regionName"`
	City        string  `json:"city"`
	Zip         string  `json:"zip"`
	Lat         float64 `json:"lat"`
	Lon         float64 `json:"lon"`
	Timezone    string  `json:"timezone"`
	ISP         string  `json:"isp"`
	Org         string  `json:"org"`
	AS          string  `json:"as"`
	Reverse     string  `json:"reverse"`
	Mobile      bool    `json:"mobile"`
	Proxy       bool    `json:"proxy"`
	Hosting     bool    `json:"hosting"`
}

// @note cleanup expired cache entries every 10 minutes
func cleanupExpiredEntries() {
	ticker := time.NewTicker(10 * time.Minute)
	defer ticker.Stop()

	for range ticker.C {
		now := time.Now()

		proxyCache.Range(func(key, value interface{}) bool {
			if entry, ok := value.(cacheEntry); ok {
				if now.After(entry.expiresAt) {
					proxyCache.Delete(key)
				}
			}
			return true
		})

		ipBlacklist.Range(func(key, value interface{}) bool {
			if entry, ok := value.(cacheEntry); ok {
				if now.After(entry.expiresAt) {
					ipBlacklist.Delete(key)
				}
			}
			return true
		})
	}
}

// @note track connection and check rate limit
func trackConnection(ip string, maxConnections, rateLimit int) (bool, string) {
	now := time.Now()

	value, _ := connectionMap.LoadOrStore(ip, &connectionTracker{
		count:      0,
		timestamps: make([]time.Time, 0),
	})

	tracker := value.(*connectionTracker)
	tracker.mutex.Lock()
	defer tracker.mutex.Unlock()

	cutoff := now.Add(-1 * time.Second)
	newTimestamps := make([]time.Time, 0)
	for _, ts := range tracker.timestamps {
		if ts.After(cutoff) {
			newTimestamps = append(newTimestamps, ts)
		}
	}
	tracker.timestamps = newTimestamps

	if len(tracker.timestamps) >= rateLimit {
		return false, fmt.Sprintf("Connection rate limit exceeded: %d/sec", rateLimit)
	}

	if tracker.count >= maxConnections {
		return false, fmt.Sprintf("Max concurrent connections exceeded: %d", maxConnections)
	}

	tracker.count++
	tracker.timestamps = append(tracker.timestamps, now)

	return true, ""
}

// @note release connection tracking
func releaseConnection(ip string) {
	value, exists := connectionMap.Load(ip)
	if !exists {
		return
	}

	tracker := value.(*connectionTracker)
	tracker.mutex.Lock()
	defer tracker.mutex.Unlock()

	if tracker.count > 0 {
		tracker.count--
	}
}

// @note check if IP is blacklisted
func isBlacklisted(ip string) bool {
	value, exists := ipBlacklist.Load(ip)
	if !exists {
		return false
	}

	if entry, ok := value.(cacheEntry); ok {
		if time.Now().After(entry.expiresAt) {
			ipBlacklist.Delete(ip)
			return false
		}
		return true
	}
	return false
}

// @note blacklist IP for 24 hours
func blacklistIP(ip string) {
	ipBlacklist.Store(ip, cacheEntry{
		value:     true,
		expiresAt: time.Now().Add(24 * time.Hour),
	})
}

// @note check if circuit breaker is open
func isCircuitBreakerOpen() bool {
	circuitBreakerMutex.RLock()
	defer circuitBreakerMutex.RUnlock()
	return circuitBreakerOpen
}

// @note open circuit breaker after 5 consecutive failures
func recordProxyCheckFailure() {
	failures := atomic.AddUint64(&circuitBreakerFailures, 1)
	if failures >= 5 {
		circuitBreakerMutex.Lock()
		circuitBreakerOpen = true
		circuitBreakerMutex.Unlock()

		go func() {
			time.Sleep(5 * time.Minute)
			circuitBreakerMutex.Lock()
			circuitBreakerOpen = false
			atomic.StoreUint64(&circuitBreakerFailures, 0)
			circuitBreakerMutex.Unlock()
			logger.Info("Circuit breaker closed, resuming proxy checks")
		}()

		logger.Warn("Circuit breaker opened due to repeated proxy check failures")
	}
}

// @note reset failure count on successful proxy check
func recordProxyCheckSuccess() {
	atomic.StoreUint64(&circuitBreakerFailures, 0)
}

// @note check if IP is proxy with caching and circuit breaker
func checkProxy(ip string) (bool, error) {
	if isCircuitBreakerOpen() {
		return false, nil
	}

	if cachedResult, found := proxyCache.Load(ip); found {
		if entry, ok := cachedResult.(cacheEntry); ok {
			if time.Now().Before(entry.expiresAt) {
				return entry.value.(bool), nil
			}
			proxyCache.Delete(ip)
		}
	}

	url := fmt.Sprintf("http://ip-api.com/json/%s?fields=proxy", ip)

	var result IPAPIResponse
	for i := 0; i < 3; i++ {
		resp, err := httpClient.Get(url)
		if err != nil {
			if i == 2 {
				recordProxyCheckFailure()
				return false, err
			}
			time.Sleep(1 * time.Second)
			continue
		}
		defer resp.Body.Close()

		if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
			recordProxyCheckFailure()
			return false, err
		}

		recordProxyCheckSuccess()
		proxyCache.Store(ip, cacheEntry{
			value:     result.Proxy,
			expiresAt: time.Now().Add(1 * time.Hour),
		})
		return result.Proxy, nil
	}

	recordProxyCheckFailure()
	return false, fmt.Errorf("failed to check proxy after 3 attempts")
}

// @note initialize HTTP server with middleware and routes
func Initialize() *fiber.App {
	logger.Info("Initializing HTTP Server")

	app := fiber.New(fiber.Config{
		DisableStartupMessage: true,
		BodyLimit:             512 * 1024,
		IdleTimeout:           10 * time.Second,
		ReadTimeout:           10 * time.Second,
		WriteTimeout:          10 * time.Second,
	})

	config := config.GetConfig()

	var db *geoip2.Reader
	var err error

	if config.EnableGeo {
		mmdbPath := "mmdb/GOWebServer-Depedencies/GeoLite2-City.mmdb"

		if _, err := os.Stat(mmdbPath); os.IsNotExist(err) {
			logger.Info("GeoLite2-City.mmdb not found, attempting to download...")
			if err := downloadGeoLite2DB(mmdbPath); err != nil {
				logger.Error("Failed to download GeoLite2-City.mmdb: ", err)
				logger.Info("Geo Location will be disabled")
				config.EnableGeo = false
			} else {
				logger.Info("GeoLite2-City.mmdb downloaded successfully")
			}
		}

		if config.EnableGeo {
			if db, err = geoip2.Open(mmdbPath); err != nil {
				logger.Error("Failed to open GeoLite2-City.mmdb: ", err)
				logger.Info("Deleting corrupted database file...")
				os.Remove(mmdbPath)
				logger.Info("Geo Location will be disabled")
				config.EnableGeo = false
			}
		}
	}

	app.Use(func(c *fiber.Ctx) error {
		if config.Logger {
			logger.Infof("[%s] %s %s", c.IP(), c.Method(), c.Path())
		}
		return c.Next()
	})

	app.Use(func(c *fiber.Ctx) error {
		ip := c.IP()

		maxConnections := 10
		rateLimit := 5

		allowed, reason := trackConnection(ip, maxConnections, rateLimit)
		if !allowed {
			if config.Logger {
				logger.Infof("DDoS protection triggered for IP %s: %s", ip, reason)
			}
			blacklistIP(ip)
			return c.Status(fiber.StatusTooManyRequests).SendString("Too many connections")
		}

		defer releaseConnection(ip)
		return c.Next()
	})

	app.Use(func(c *fiber.Ctx) error {
		bodySize := len(c.Body())
		maxSize := 512 * 1024
		if bodySize > maxSize {
			if config.Logger {
				logger.Infof("Payload too large from IP %s: %d bytes (max: %d)", c.IP(), bodySize, maxSize)
			}
			return c.Status(fiber.StatusRequestEntityTooLarge).SendString("Payload too large")
		}
		return c.Next()
	})

	app.Use(cors.New())
	app.Use(recover.New())
	app.Use(compress.New())
	app.Use(limiter.New(limiter.Config{
		Max:        config.RateLimit,
		Expiration: time.Duration(config.RateLimitDuration) * time.Minute,
		LimitReached: func(c *fiber.Ctx) error {
			if config.Logger {
				logger.Infof("IP %s is rate limited", c.IP())
			}
			blacklistIP(c.IP())
			return c.Status(fiber.StatusTooManyRequests).SendString("Too many requests, please try again later.")
		},
	}))

	app.Use(func(c *fiber.Ctx) error {
		if isBlacklisted(c.IP()) {
			return c.Status(fiber.StatusForbidden).SendString("Your IP has been blacklisted due to suspicious activity.")
		}

		isProxy, err := checkProxy(c.IP())
		if err != nil {
			if config.Logger {
				logger.Error("Error checking proxy for IP ", c.IP(), ": ", err)
			}
		}
		if isProxy {
			if config.Logger {
				logger.Warn("Proxy detected: ", c.IP())
			}
			blacklistIP(c.IP())
			return c.Status(fiber.StatusForbidden).SendString("Access denied: Proxy detected")
		}

		return c.Next()
	})

	app.Use(func(c *fiber.Ctx) error {
		if !config.EnableGeo {
			return c.Next()
		}

		if db == nil {
			return c.Next()
		}

		ip := net.ParseIP(c.IP())
		if ip == nil {
			if config.Logger {
				logger.Error("Invalid IP address: ", c.IP())
			}
			return c.Status(fiber.StatusBadRequest).SendString("Invalid IP address")
		}

		record, err := db.City(ip)
		if err != nil {
			if config.Logger {
				logger.Error("GeoIP lookup failed for IP ", c.IP(), ": ", err)
			}
			return c.Next()
		}

		if config.Logger {
			if record != nil {
				logger.Infof("IP: %s, Country: %s, City: %s", c.IP(), record.Country.Names["en"], record.City.Names["en"])
			} else {
				logger.Infof("IP: %s", c.IP())
			}
		}

		if len(config.GeoLocation) > 0 && record != nil {
			allowed := false
			for _, loc := range config.GeoLocation {
				if record.Country.IsoCode == loc {
					allowed = true
					break
				}
			}
			if !allowed {
				return c.Status(fiber.StatusForbidden).SendString("Access denied: Region not allowed")
			}
		}

		return c.Next()
	})

	cdnUrl := config.ServerCdn
	if cdnUrl == "default" {
		cdnUrl = "0098/5858486/"
	}

	app.Use(func(c *fiber.Ctx) error {
		if strings.HasPrefix(c.Path(), "/cache") {
			pathname := filepath.Join("./cache", c.Path())

			if _, err := os.Stat(pathname); os.IsNotExist(err) {
				if config.Logger {
					logger.Info("Connection from: " + c.IP() + " | Fetching file from CDN: " + c.Path())
				}
				return c.Redirect(
					fmt.Sprintf("https://ubistatic-a.akamaihd.net/%s%s", cdnUrl, c.Path()),
					fiber.StatusMovedPermanently,
				)
			}

			ext := filepath.Ext(c.Path())
			if contentType, ok := contentTypes[ext]; ok {
				c.Set("Content-Type", contentType)
			}

			if err := c.SendFile(pathname); err != nil {
				if config.Logger {
					logger.Error("Failed to send file ", pathname, ": ", err)
				}
				return c.Status(fiber.StatusInternalServerError).SendString("Failed to serve file")
			}
			return nil
		}
		return c.Next()
	})

	app.Get("/", func(c *fiber.Ctx) error {
		return c.SendString("Hello, World!")
	})

	meta := config.ServerMeta
	if meta == "" {
		meta = "default"
	}

	loginUrl := config.LoginUrl
	if loginUrl == "default" {
		loginUrl = "login-web-sigma.vercel.app"
	}
	content := fmt.Sprintf(
		"server|%s\n"+
			"port|%s\n"+
			"type|1\n"+
			"# maint|Server is currently down for maintenance. We will be back soon!\n"+
			"loginurl|%s\n"+
			"meta|%s\n"+
			"RTENDMARKERBS1001",
		config.Host, config.Port, loginUrl, meta)

	app.Post("/growtopia/server_data.php", func(c *fiber.Ctx) error {
		if c.Get("User-Agent") == "" || !strings.Contains(c.Get("User-Agent"), "UbiServices_SDK") {
			return c.SendStatus(fiber.StatusForbidden)
		}
		return c.SendString(content)
	})

	app.Use(func(c *fiber.Ctx) error {
		return c.Status(fiber.StatusNotFound).SendString("404 Not Found")
	})

	go cleanupExpiredEntries()

	return app
}

// @note start HTTP server with graceful shutdown
func Start(app *fiber.App) {
	logger.Info("Starting HTTP Server")

	go func() {
		if err := app.ListenTLS(":443", "ssl/server.crt", "ssl/server.key"); err != nil {
			log.Fatal(err)
		}
	}()

	sigChan := make(chan os.Signal, 1)
	signal.Notify(sigChan, os.Interrupt, syscall.SIGTERM)
	<-sigChan

	logger.Info("Shutting down server gracefully...")
	if err := app.ShutdownWithTimeout(30 * time.Second); err != nil {
		logger.Error("Error during shutdown:", err)
	}
	logger.Info("Server stopped")
}
