package http

import (
    "encoding/json"
    "fmt"
    "io"
    "log"
    "math/rand"
    "net"
    "net/http"
    "os"
    "path/filepath"
    "runtime"
    "strings"
    "sync"
    "sync/atomic"
    "syscall"
    "time"
    "unsafe"

    "github.com/gofiber/fiber/v2"
    "github.com/gofiber/fiber/v2/middleware/compress"
    "github.com/gofiber/fiber/v2/middleware/cors"
    "github.com/gofiber/fiber/v2/middleware/limiter"
    "github.com/gofiber/fiber/v2/middleware/recover"
    "github.com/oschwald/geoip2-golang"
    "github.com/yoruakio/gowebserver/config"
    "github.com/yoruakio/gowebserver/logger"
)

var (
    requestCount  uint64
    bytesReceived uint64
    ipBlacklist   sync.Map
)

type IPAPIResponse struct {
    Query        string `json:"query"`
    Status       string `json:"status"`
    Country      string `json:"country"`
    CountryCode  string `json:"countryCode"`
    Region       string `json:"region"`
    RegionName   string `json:"regionName"`
    City         string `json:"city"`
    Zip          string `json:"zip"`
    Lat          float64 `json:"lat"`
    Lon          float64 `json:"lon"`
    Timezone     string `json:"timezone"`
    ISP          string `json:"isp"`
    Org          string `json:"org"`
    AS           string `json:"as"`
    Reverse      string `json:"reverse"`
    Mobile       bool   `json:"mobile"`
    Proxy        bool   `json:"proxy"`
    Hosting      bool   `json:"hosting"`
}

func setConsoleTitle(title string) {
    kernel32, _ := syscall.LoadLibrary("kernel32.dll")
    setConsoleTitle, _ := syscall.GetProcAddress(kernel32, "SetConsoleTitleW")
    syscall.Syscall(setConsoleTitle, 1, uintptr(unsafe.Pointer(syscall.StringToUTF16Ptr(title))), 0, 0)
}

func updateConsoleTitle() {
    title := fmt.Sprintf("GOWebServer by YoruAkio | Requests: %d, Bytes: %d", atomic.LoadUint64(&requestCount), atomic.LoadUint64(&bytesReceived))
    setConsoleTitle(title)
}

func triggerGarbageCollection() {
    for {
        time.Sleep(1 * time.Minute) // Adjust the interval as needed
        runtime.GC()
    }
}

func isBlacklisted(ip string) bool {
    _, blacklisted := ipBlacklist.Load(ip)
    return blacklisted
}

func blacklistIP(ip string) {
    ipBlacklist.Store(ip, struct{}{})
}

func checkProxy(ip string) (bool, error) {
    url := fmt.Sprintf("http://ip-api.com/json/%s?fields=proxy", ip)
    resp, err := http.Get(url)
    if err != nil {
        return false, err
    }
    defer resp.Body.Close()

    var result IPAPIResponse
    if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
        return false, err
    }

    return result.Proxy, nil
}

func Initialize() *fiber.App {
    logger.Info("Initializing HTTP Server")

    app := fiber.New(fiber.Config{
        DisableStartupMessage: true,
        BodyLimit:             512 * 1024, // 512KB of body limit
        IdleTimeout:           10 * time.Second,
        ReadTimeout:           10 * time.Second,
        WriteTimeout:          10 * time.Second,
    })

    config := config.GetConfig()

    var db *geoip2.Reader
    var err error

    if config.EnableGeo {
        if db, err = geoip2.Open("mmdb/GOWebServer-Depedencies/GeoLite2-City.mmdb"); err != nil {
            logger.Error("Failed to open GeoLite2-City.mmdb, did you use --recursive when cloning the repository? read the README.md for more information")
            logger.Error(err)
        }
    }

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
            logger.Error("Error checking proxy:", err)
            return c.Status(fiber.StatusInternalServerError).SendString("Internal Server Error")
        }
        if isProxy {
            return c.Status(fiber.StatusForbidden).SendString("Access denied: Proxy detected")
        }

        atomic.AddUint64(&requestCount, 1)
        atomic.AddUint64(&bytesReceived, uint64(len(c.Body())))
        updateConsoleTitle()
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
        record, err := db.City(ip)
        if err != nil {
            logger.Error(err)
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
                return c.Status(fiber.StatusForbidden).SendString("IP is not in the allowed GeoLocation")
            }
        }

        return c.Next()
    })

    app.Use(func(c *fiber.Ctx) error {
        if config.Logger {
            logger.Infof("[%s] %s %s => %d", c.IP(), c.Method(), c.Path(), c.Response().StatusCode())
        }
        return c.Next()
    })

    app.Static("/cache", "./cache")

    app.Use(func(c *fiber.Ctx) error {
        if strings.HasPrefix(c.Path(), "/cache") {
            pathname := filepath.Join("./cache", c.Path())

            if config.ServerCdn == "default" {
                config.ServerCdn = "0098/5858486/"
            }

            if _, err := os.Stat(pathname); os.IsNotExist(err) {
                c.Redirect(
                    fmt.Sprintf("https://ubistatic-a.akamaihd.net/%s%s", config.ServerCdn, c.Path()),
                    fiber.StatusMovedPermanently,
                )

                logger.Info("Connection from: " + c.IP() + " | Fetching file from CDN: " + c.Path())
                return nil
            }

            file, err := os.Open(pathname)
            if err != nil {
                return c.Status(fiber.StatusNotFound).SendString("error from loading")
            }
            defer file.Close()

            buffer, err := io.ReadAll(file)
            if err != nil {
                return c.Status(fiber.StatusNotFound).SendString("error")
            }

            contentTypes := map[string]string{
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

            ext := filepath.Ext(c.Path())
            c.Set("Content-Type", contentTypes[ext])

            return c.Send(buffer)
        }
        return c.Next()
    })

    app.Get("/", func(c *fiber.Ctx) error {
        return c.SendString("Hello, World!")
    })

    meta := fmt.Sprintf("K10WA_%d", rand.Intn(9000)+1000)
    loginUrl := config.LoginUrl
    if loginUrl == "default" {
        loginUrl = "private.yoruakio.tech" // default login url that i built for public use
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

    go triggerGarbageCollection()

    return app
}

func Start(app *fiber.App) {
    logger.Info("Starting HTTP Server")

    log.Fatal(app.ListenTLS(":443", "ssl/server.crt", "ssl/server.key"))
}