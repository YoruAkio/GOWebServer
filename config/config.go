package config

import (
	"encoding/json"
	"io"
	"log"
	"os"
)

type Config struct {
	// Growtopia Server Configuration
	Host     string `json:"host"`
	Port     string `json:"port"`
	LoginUrl string `json:"loginUrl"`
	ServerCdn string `json:"serverCdn"`
	ServerMeta string `json:'serverMeta'`

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

	isLoaded = true
	return config
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
		LoginUrl:          "default", // default login url is private.yoruakio.tech
		ServerCdn:         "default", // default cdn is 
		Logger:            true,
		RateLimit:         300, // 300 requests per minute( default )
		RateLimitDuration: 5,   // 5 minutes of rate limit cooldown ( default )
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
