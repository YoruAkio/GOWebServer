package config

import (
	"encoding/json"
	"fmt"
	"io"
	"log"
	"os"
)

type Config struct {
	// Growtopia Server Configuration
	Host       string `json:"host"`
	Port       string `json:"port"`
	LoginUrl   string `json:"loginUrl"`
	ServerCdn  string `json:"serverCdn"`
	ServerMeta string `json:"serverMeta"`

	// Logger Configuration
	Logger bool `json:"isLogging"`

	// Rate Limiter Configuration
	RateLimit         int `json:"rateLimit"`
	RateLimitDuration int `json:"rateLimitDuration"`

	// Geo Location Configuration
	GeoLocation []string `json:"trustedRegions"`
	EnableGeo   bool     `json:"enableGeo"`
}

var config Config
var isLoaded bool

// @note load config from JSON file with validation
func LoadConfig() Config {
	if _, err := os.Stat("config.json"); os.IsNotExist(err) {
		config = CreateConfig()
		isLoaded = true
		return config
	}

	file, err := os.Open("config.json")
	if err != nil {
		log.Fatal(err)
	}
	defer file.Close()

	data, err := io.ReadAll(file)
	if err != nil {
		log.Fatal(err)
	}

	err = json.Unmarshal(data, &config)
	if err != nil {
		log.Fatal(err)
	}

	if err := ValidateConfig(&config); err != nil {
		log.Fatal("Config validation failed: ", err)
	}

	isLoaded = true
	return config
}

// @note validate config values
func ValidateConfig(cfg *Config) error {
	if cfg.Host == "" {
		return fmt.Errorf("host cannot be empty")
	}
	if cfg.Port == "" {
		return fmt.Errorf("port cannot be empty")
	}
	if cfg.RateLimit <= 0 {
		return fmt.Errorf("rateLimit must be greater than 0")
	}
	if cfg.RateLimitDuration <= 0 {
		return fmt.Errorf("rateLimitDuration must be greater than 0")
	}
	return nil
}

func GetConfig() Config {
	if !isLoaded {
		log.Fatal("LoadConfig() is not called")
	}
	return config
}

func CreateConfig() Config {
	config := Config{
		Host:              "127.0.0.1",
		Port:              "17091",
		LoginUrl:          "default",
		ServerCdn:         "default",
		Logger:            true,
		RateLimit:         300,
		RateLimitDuration: 5,
		EnableGeo:         false,
		GeoLocation:       []string{"ID", "SG", "MY"},
	}

	data, err := json.MarshalIndent(config, "", "    ")
	if err != nil {
		log.Fatal(err)
	}

	err = os.WriteFile("config.json", data, 0666)
	if err != nil {
		log.Fatal(err)
	}

	return config
}
