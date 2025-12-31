package logger

import (
	"fmt"
	"os"

	"github.com/sirupsen/logrus"
)

var log = logrus.New()

// @note custom plain formatter for cross-platform compatibility
type plainFormatter struct{}

func (f *plainFormatter) Format(entry *logrus.Entry) ([]byte, error) {
	timestamp := entry.Time.Format("15:04")
	level := entry.Level.String()

	switch entry.Level {
	case logrus.InfoLevel:
		level = "INFO"
	case logrus.WarnLevel:
		level = "WARN"
	case logrus.ErrorLevel:
		level = "ERROR"
	case logrus.FatalLevel:
		level = "FATAL"
	case logrus.DebugLevel:
		level = "DEBUG"
	}

	msg := fmt.Sprintf("%s - %s - %s\n", level, timestamp, entry.Message)
	return []byte(msg), nil
}

func init() {
	log.SetOutput(os.Stdout)
	log.SetFormatter(&plainFormatter{})
	log.SetLevel(logrus.InfoLevel)
}

func Info(args ...interface{}) {
	log.Info(args...)
}

func Infof(format string, args ...interface{}) {
	log.Infof(format, args...)
}

func Debug(args ...interface{}) {
	log.Debug(args...)
}

func Error(args ...interface{}) {
	log.Error(args...)
}

func Fatal(args ...interface{}) {
	log.Fatal(args...)
}

func Warn(args ...interface{}) {
	log.Warn(args...)
}
