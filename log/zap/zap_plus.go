package zap

import (
	"fmt"
	"log/syslog"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"github.com/natefinch/lumberjack"
	"go.uber.org/zap"
	"go.uber.org/zap/zapcore"
)

var (
	zapLoggerInstance *zap.Logger
	zapMu             sync.RWMutex
)

// ZapFileConfig 文件日志配置
type ZapFileConfig struct {
	Path        string        // 日志文件路径
	NameFormat  string        // 日志文件名格式，支持日期占位符，如: app-{date}.log
	Permissions os.FileMode   // 日志文件权限
	Level       zapcore.Level // 日志记录级别，只记录大于等于该级别的日志
	MaxSize     int           // 每个日志文件的最大大小（MB）
	MaxBackups  int           // 保留的旧日志文件最大数量
	MaxAge      int           // 保留的旧日志文件最大天数
	Compress    bool          // 是否压缩旧日志文件
}

// ZapSyslogConfig 远程syslog配置
type ZapSyslogConfig struct {
	Network  string          // 网络类型：udp或tcp
	Addr     string          // 远程syslog服务器地址，格式：host:port
	Priority syslog.Priority // 日志优先级
	Tag      string          // 日志标签
	Level    zapcore.Level   // 日志记录级别
}

// DefaultZapFileConfig 默认文件日志配置
var DefaultZapFileConfig = ZapFileConfig{
	Path:        "data/logs",
	NameFormat:  "app-{date}.log",
	Permissions: 0666,
	MaxSize:     100,  // 默认每个文件最大100MB
	MaxBackups:  30,   // 默认保留30个旧文件
	MaxAge:      7,    // 默认保留7天
	Compress:    true, // 默认压缩旧文件
}

// DefaultZapSyslogConfig 默认远程syslog配置
var DefaultZapSyslogConfig = ZapSyslogConfig{
	Network:  "udp",
	Addr:     "127.0.0.1:514",
	Priority: syslog.LOG_INFO | syslog.LOG_LOCAL0,
	Tag:      "go-learn",
	Level:    zapcore.InfoLevel,
}

// InitZapConfig zap初始化配置
type InitZapConfig struct {
	Tag          string
	Outputs      string
	Level        zapcore.Level // 全局日志级别
	FileConfig   *ZapFileConfig
	SyslogConfig *ZapSyslogConfig
}

// InitZapLogger 初始化zap日志系统
func InitZapLogger(tag string, outputs string) error {
	return InitZapLoggerWithConfig(InitZapConfig{
		Tag:     tag,
		Outputs: outputs,
		Level:   zapcore.DebugLevel,
	})
}

// InitZapLoggerWithConfig 使用配置初始化zap日志系统
func InitZapLoggerWithConfig(config InitZapConfig) error {
	zapMu.Lock()
	defer zapMu.Unlock()

	var cores []zapcore.Core

	// 解析输出配置
	outputTypes := strings.Split(config.Outputs, ",")
	for _, output := range outputTypes {
		switch strings.TrimSpace(output) {
		case "file":
			// 使用自定义配置或默认配置创建文件core
			fileConfig := DefaultZapFileConfig
			if config.FileConfig != nil {
				fileConfig = *config.FileConfig
			}
			fileCore, err := createFileCore(fileConfig)
			if err != nil {
				return err
			}
			cores = append(cores, fileCore)
		case "syslog":
			// 使用自定义配置或默认配置创建远程syslog core
			syslogConfig := DefaultZapSyslogConfig
			if config.SyslogConfig != nil {
				syslogConfig = *config.SyslogConfig
			}
			syslogConfig.Tag = config.Tag
			syslogCore, err := createSyslogCore(syslogConfig)
			if err != nil {
				return err
			}
			cores = append(cores, syslogCore)
		case "console":
			// 创建控制台core
			encoder := zapcore.NewConsoleEncoder(zapcore.EncoderConfig{
				TimeKey:        "time",
				LevelKey:       "level",
				NameKey:        "logger",
				CallerKey:      "caller",
				MessageKey:     "msg",
				StacktraceKey:  "stacktrace",
				EncodeLevel:    zapcore.CapitalColorLevelEncoder,
				EncodeTime:     zapcore.ISO8601TimeEncoder,
				EncodeDuration: zapcore.SecondsDurationEncoder,
				EncodeCaller:   zapcore.ShortCallerEncoder,
			})
			consoleCore := zapcore.NewCore(
				encoder,
				zapcore.AddSync(os.Stdout),
				config.Level,
			)
			cores = append(cores, consoleCore)
		}
	}

	// 创建多core的logger
	core := zapcore.NewTee(cores...)
	zapLoggerInstance = zap.New(core, zap.AddCaller())

	return nil
}

// createFileCore 创建文件日志core
func createFileCore(config ZapFileConfig) (zapcore.Core, error) {
	// 确保日志目录存在
	if err := os.MkdirAll(config.Path, config.Permissions); err != nil {
		return nil, fmt.Errorf("创建日志目录失败: %v", err)
	}

	// 生成当前日志文件名
	currentTime := time.Now()
	fileName := strings.Replace(config.NameFormat, "{date}", currentTime.Format("2006-01-02"), -1)
	logPath := filepath.Join(config.Path, fileName)

	// 使用 lumberjack 进行日志分割
	writeSyncer := zapcore.AddSync(&lumberjack.Logger{
		Filename:   logPath,
		MaxSize:    config.MaxSize, // MB
		MaxBackups: config.MaxBackups,
		MaxAge:     config.MaxAge, // days
		Compress:   config.Compress,
	})

	// 创建encoder
	encoder := zapcore.NewJSONEncoder(zapcore.EncoderConfig{
		TimeKey:        "time",
		LevelKey:       "level",
		NameKey:        "logger",
		CallerKey:      "caller",
		MessageKey:     "msg",
		StacktraceKey:  "stacktrace",
		EncodeLevel:    zapcore.LowercaseLevelEncoder,
		EncodeTime:     zapcore.ISO8601TimeEncoder,
		EncodeDuration: zapcore.SecondsDurationEncoder,
		EncodeCaller:   zapcore.ShortCallerEncoder,
	})

	return zapcore.NewCore(
		encoder,
		writeSyncer,
		config.Level,
	), nil
}

// createSyslogCore 创建远程syslog core
func createSyslogCore(config ZapSyslogConfig) (zapcore.Core, error) {
	if config.Network == "" || config.Addr == "" {
		return nil, fmt.Errorf("syslog网络类型或地址不能为空")
	}
	// 连接syslog服务器
	writer, err := syslog.Dial(config.Network, config.Addr, config.Priority, config.Tag)
	if err != nil {
		return nil, err
	}

	// 创建encoder
	encoder := zapcore.NewJSONEncoder(zapcore.EncoderConfig{
		TimeKey:        "time",
		LevelKey:       "level",
		NameKey:        "logger",
		CallerKey:      "caller",
		MessageKey:     "msg",
		StacktraceKey:  "stacktrace",
		EncodeLevel:    zapcore.LowercaseLevelEncoder,
		EncodeTime:     zapcore.ISO8601TimeEncoder,
		EncodeDuration: zapcore.SecondsDurationEncoder,
		EncodeCaller:   zapcore.ShortCallerEncoder,
	})

	return zapcore.NewCore(
		encoder,
		zapcore.AddSync(writer),
		config.Level,
	), nil
}

// Debug 记录调试日志
func Debug(msg string, fields ...zap.Field) {
	zapMu.RLock()
	defer zapMu.RUnlock()
	zapLoggerInstance.Debug(msg, fields...)
}

// Info 记录信息日志
func Info(msg string, fields ...zap.Field) {
	zapMu.RLock()
	defer zapMu.RUnlock()
	zapLoggerInstance.Info(msg, fields...)
}

// Warn 记录警告日志
func Warn(msg string, fields ...zap.Field) {
	zapMu.RLock()
	defer zapMu.RUnlock()
	zapLoggerInstance.Warn(msg, fields...)
}

// Error 记录错误日志
func Error(msg string, fields ...zap.Field) {
	zapMu.RLock()
	defer zapMu.RUnlock()
	zapLoggerInstance.Error(msg, fields...)
}

// Fatal 记录致命错误日志
func Fatal(msg string, fields ...zap.Field) {
	zapMu.RLock()
	defer zapMu.RUnlock()
	zapLoggerInstance.Fatal(msg, fields...)
}
