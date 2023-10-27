package arkssh

import "go.uber.org/zap"

func NewLogger() (*zap.Logger, error) {
	cfg := zap.NewDevelopmentConfig()
	cfg.OutputPaths = []string{
		"log.log",
		"stdout",
	}
	return cfg.Build()
}

func InitLogger() {
	logger, _ := NewLogger()
	zap.ReplaceGlobals(logger)
}
