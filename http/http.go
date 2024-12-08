package http

import (
    "fmt"
    "io"
    "log"
    "math/rand"
    "net"
    "os"
    "path/filepath"
    "strings"
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
    requestCount uint64
    bytesReceived uint64
)

func setConsoleTitle(title string) {
    kernel32, _ := syscall.LoadLibrary("kernel32.dll")
    setConsoleTitle, _ := syscall.GetProcAddress(kernel32, "SetConsoleTitleW")
    syscall.Syscall(setConsoleTitle, 1, uintptr(unsafe.Pointer(syscall.StringToUTF16Ptr(title))), 0, 0)
}

func updateConsoleTitle() {
    title := fmt.Sprintf("GOWebServer by YoruAkio | Requests: %d, Bytes: %d", atomic.LoadUint64(&requestCount), atomic.LoadUint64(&bytesReceived))
    setConsoleTitle(title)
}

func Initialize() *fiber.App {
    logger.Info("Initializing HTTP Server")

    app := fiber.New(fiber.Config{
        DisableStartupMessage: true,
        BodyLimit:             512 * 1024, // 512KB of body limit
        IdleTimeout:           30 * time.Second,
        ReadTimeout:           30 * time.Second,
        WriteTimeout:          30 * time.Second,
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
            return c.Status(fiber.StatusTooManyRequests).SendString("Too many requests, please try again later.")
        },
    }))

    app.Use(func(c *fiber.Ctx) error {
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
            go func() {
                logger.Info("Connection from: " + c.IP() + " | Getting: " + c.Path())

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

                    return
                }

                file, err := os.Open(pathname)
                if err != nil {
                    c.Status(fiber.StatusNotFound).SendString("error from loading")
                    return
                }
                defer file.Close()

                buffer, err := io.ReadAll(file)
                if err != nil {
                    c.Status(fiber.StatusNotFound).SendString("error")
                    return
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

                c.Send(buffer)
            }()
            return nil
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

    return app
}

func Start(app *fiber.App) {
    logger.Info("Starting HTTP Server")

    log.Fatal(app.ListenTLS(":443", "ssl/server.crt", "ssl/server.key"))
}