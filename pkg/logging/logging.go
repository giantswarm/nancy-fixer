package logging

import (
	"io"

	"github.com/pkg/errors"
	"github.com/pterm/pterm"
)

type LoggerConfig struct {
	Level     pterm.LogLevel
	Formatter pterm.LogFormatter
	Writer    io.Writer
	ShowTime  bool
}

func LogLevelFromString(level string) (pterm.LogLevel, error) {
	switch level {
	case "disabled":
		return pterm.LogLevelDisabled, nil
	case "trace":
		return pterm.LogLevelTrace, nil
	case "debug":
		return pterm.LogLevelDebug, nil
	case "info":
		return pterm.LogLevelInfo, nil
	case "warn":
		return pterm.LogLevelWarn, nil
	case "error":
		return pterm.LogLevelError, nil
	case "fatal":
		return pterm.LogLevelFatal, nil
	case "print":
		return pterm.LogLevelPrint, nil
	default:
		return pterm.LogLevelInfo, errors.Cause(errInvalidLogLevel)
	}
}

func LogFormatterFromString(formatter string) (pterm.LogFormatter, error) {
	switch formatter {
	case "colorful":
		return pterm.LogFormatterColorful, nil
	case "json":
		return pterm.LogFormatterJSON, nil
	}
	return pterm.LogFormatterColorful, errors.Cause(errInvalidLogFormatterError)
}

func MakeLogger(c LoggerConfig) *pterm.Logger {
	logger := pterm.DefaultLogger.WithLevel(c.Level).WithFormatter(c.Formatter)
	logger.Writer = c.Writer
	logger.ShowTime = c.ShowTime

	return logger
}

func LogSection(logger *pterm.Logger, msg string) {
	switch logger.Formatter {
	case pterm.LogFormatterColorful:
		pterm.DefaultSection.Println(msg)
	case pterm.LogFormatterJSON:
		logger.Info(msg)
	}
}
