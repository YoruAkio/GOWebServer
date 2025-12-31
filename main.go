package main

import (
	"github.com/yoruakio/gowebserver/config"
	"github.com/yoruakio/gowebserver/http"
	"github.com/yoruakio/gowebserver/logger"
)

func main() {
	config.LoadConfig()

	cfg := config.GetConfig()

	logger.Info("=== Server Configuration ===")
	logger.Infof("Host: %s:%s", cfg.Host, cfg.Port)
	logger.Infof("Login URL: %s", cfg.LoginUrl)
	logger.Infof("Server CDN: %s", cfg.ServerCdn)
	if cfg.ServerMeta != "" {
		logger.Infof("Server Meta: %s", cfg.ServerMeta)
	}
	logger.Infof("Logging: %v", cfg.Logger)
	logger.Infof("Rate Limit: %d requests per %d minutes", cfg.RateLimit, cfg.RateLimitDuration)
	if cfg.EnableGeo {
		logger.Infof("Geo Location: Enabled (Regions: %v)", cfg.GeoLocation)
	} else {
		logger.Info("Geo Location: Disabled")
	}
	logger.Info("===========================")

	app := http.Initialize()
	http.Start(app)
}
