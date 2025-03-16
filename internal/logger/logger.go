package logger

import (
	"fmt"
	"io"
	"log"
	"os"
)

// ANSI color codes
const (
	colorReset  = "\033[0m"
	colorRed    = "\033[31m"
	colorYellow = "\033[33m"
	colorBlue   = "\033[34m"
	colorGray   = "\033[37m"
	colorGreen  = "\033[32m"
	colorPurple = "\033[35m"
)

// Log levels
const (
	LevelError = iota
	LevelWarning
	LevelInfo
	LevelDebug
)

var (
	// Different log levels with colors
	Info    *log.Logger
	Debug   *log.Logger
	Warning *log.Logger
	Error   *log.Logger

	// Control overall logging level
	LogLevel = LevelInfo

	// Control color output
	useColors = true
)

// Initialize sets up the loggers with the specified output
func Initialize(infoHandle, debugHandle, warningHandle, errorHandle io.Writer) {
	// Default to stdout/stderr if not specified
	if infoHandle == nil {
		infoHandle = os.Stdout
	}
	if debugHandle == nil {
		debugHandle = os.Stdout
	}
	if warningHandle == nil {
		warningHandle = os.Stdout
	}
	if errorHandle == nil {
		errorHandle = os.Stderr
	}

	// Create the loggers with colored prefixes
	if useColors {
		Info = log.New(infoHandle, colorBlue+"INFO: "+colorReset, log.Ldate|log.Ltime|log.Lshortfile)
		Debug = log.New(debugHandle, colorPurple+"DEBUG: "+colorReset, log.Ldate|log.Ltime|log.Lshortfile)
		Warning = log.New(warningHandle, colorYellow+"WARNING: "+colorReset, log.Ldate|log.Ltime|log.Lshortfile)
		Error = log.New(errorHandle, colorRed+"ERROR: "+colorReset, log.Ldate|log.Ltime|log.Lshortfile)
	} else {
		Info = log.New(infoHandle, "INFO: ", log.Ldate|log.Ltime|log.Lshortfile)
		Debug = log.New(debugHandle, "DEBUG: ", log.Ldate|log.Ltime|log.Lshortfile)
		Warning = log.New(warningHandle, "WARNING: ", log.Ldate|log.Ltime|log.Lshortfile)
		Error = log.New(errorHandle, "ERROR: ", log.Ldate|log.Ltime|log.Lshortfile)
	}
}

// EnableColors enables colored output
func EnableColors() {
	useColors = true
	// Re-initialize to apply the change
	Initialize(nil, nil, nil, nil)
}

// DisableColors disables colored output
func DisableColors() {
	useColors = false
	// Re-initialize to apply the change
	Initialize(nil, nil, nil, nil)
}

// SetLevel sets the logging level
func SetLevel(level int) {
	if level >= LevelError && level <= LevelDebug {
		LogLevel = level
	}
}

// Helper functions with level checking
func Infof(format string, v ...interface{}) {
	if LogLevel >= LevelInfo {
		Info.Output(2, fmt.Sprintf(format, v...))
	}
}

func Debugf(format string, v ...interface{}) {
	if LogLevel >= LevelDebug {
		Debug.Output(2, fmt.Sprintf(format, v...))
	}
}

func Warningf(format string, v ...interface{}) {
	if LogLevel >= LevelWarning {
		Warning.Output(2, fmt.Sprintf(format, v...))
	}
}

func Errorf(format string, v ...interface{}) {
	if LogLevel >= LevelError {
		Error.Output(2, fmt.Sprintf(format, v...))
	}
}

// Simple non-formatted versions
func InfoLog(v ...interface{}) {
	if LogLevel >= LevelInfo {
		Info.Output(2, fmt.Sprint(v...))
	}
}

func DebugLog(v ...interface{}) {
	if LogLevel >= LevelDebug {
		Debug.Output(2, fmt.Sprint(v...))
	}
}

func WarningLog(v ...interface{}) {
	if LogLevel >= LevelWarning {
		Warning.Output(2, fmt.Sprint(v...))
	}
}

func ErrorLog(v ...interface{}) {
	if LogLevel >= LevelError {
		Error.Output(2, fmt.Sprint(v...))
	}
}

// Init is called automatically to initialize the logger with defaults
func init() {
	Initialize(nil, nil, nil, nil)
}
