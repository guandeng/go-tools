package zerolog

import (
	"fmt"
	"io"
	"log/syslog"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"github.com/natefinch/lumberjack"
	"github.com/rs/zerolog"
)

var (
	zerologInstance zerolog.Logger
	zerologMu       sync.RWMutex
)

// ZerologFileConfig 文件日志配置
type ZerologFileConfig struct {
	Path        string        // 日志文件路径
	NameFormat  string        // 日志文件名格式，支持日期占位符，如: app-{date}.log
	Permissions os.FileMode   // 日志文件权限
	Level       zerolog.Level // 日志记录级别
	MaxSize     int           // 每个日志文件的最大大小（MB）
	MaxBackups  int           // 保留的旧日志文件最大数量
	MaxAge      int           // 保留的旧日志文件最大天数
	Compress    bool          // 是否压缩旧日志文件
}

// ZerologSyslogConfig 远程syslog配置
type ZerologSyslogConfig struct {
	Network  string          // 网络类型：udp或tcp
	Addr     string          // 远程syslog服务器地址，格式：host:port
	Priority syslog.Priority // 日志优先级
	Tag      string          // 日志标签
	Level    zerolog.Level   // 日志记录级别
}

// DefaultZerologFileConfig 默认文件日志配置
var DefaultZerologFileConfig = ZerologFileConfig{
	Path:        "data/logs",
	NameFormat:  "app-{date}.log",
	Permissions: 0666,
	Level:       zerolog.DebugLevel,
	MaxSize:     100,  // 默认每个文件最大100MB
	MaxBackups:  30,   // 默认保留30个旧文件
	MaxAge:      7,    // 默认保留7天
	Compress:    true, // 默认压缩旧文件
}

// DefaultZerologSyslogConfig 默认远程syslog配置
var DefaultZerologSyslogConfig = ZerologSyslogConfig{
	Network:  "udp",
	Addr:     "127.0.0.1:514",
	Priority: syslog.LOG_INFO | syslog.LOG_LOCAL0,
	Tag:      "app",
	Level:    zerolog.DebugLevel,
}

// InitZerologConfig zerolog初始化配置
type InitZerologConfig struct {
	Tag          string
	Outputs      string
	Level        zerolog.Level // 全局日志级别
	FileConfig   *ZerologFileConfig
	SyslogConfig *ZerologSyslogConfig
}

// InitZerolog 初始化zerolog日志系统
func InitZerolog(config InitZerologConfig) error {
	zerologMu.Lock()
	defer zerologMu.Unlock()

	var writers []io.Writer

	// 解析输出配置
	outputTypes := strings.Split(config.Outputs, ",")
	for _, output := range outputTypes {
		switch strings.TrimSpace(output) {
		case "file":
			// 使用自定义配置或默认配置创建文件writer
			fileConfig := DefaultZerologFileConfig
			if config.FileConfig != nil {
				fileConfig = *config.FileConfig
			}
			fileWriter, err := createFileWriter(fileConfig)
			if err != nil {
				return err
			}
			writers = append(writers, fileWriter)
		case "syslog":
			// 使用自定义配置或默认配置创建远程syslog writer
			syslogConfig := DefaultZerologSyslogConfig
			if config.SyslogConfig != nil {
				syslogConfig = *config.SyslogConfig
			}
			syslogConfig.Tag = config.Tag
			syslogWriter, err := createSyslogWriter(syslogConfig)
			if err != nil {
				return err
			}
			writers = append(writers, syslogWriter)
		case "console":
			// 创建控制台writer
			consoleWriter := zerolog.ConsoleWriter{
				Out:        os.Stdout,
				TimeFormat: time.RFC3339,
			}
			writers = append(writers, consoleWriter)
		}
	}

	// 创建多writer的logger
	multi := zerolog.MultiLevelWriter(writers...)
	zerologInstance = zerolog.New(multi).Level(config.Level).With().Timestamp().Logger()

	return nil
}

// createFileWriter 创建文件日志writer
func createFileWriter(config ZerologFileConfig) (io.Writer, error) {
	// 确保日志目录存在
	if err := os.MkdirAll(config.Path, config.Permissions); err != nil {
		return nil, fmt.Errorf("创建日志目录失败: %v", err)
	}

	// 生成当前日志文件名
	currentTime := time.Now()
	fileName := strings.Replace(config.NameFormat, "{date}", currentTime.Format("2006-01-02"), -1)
	logPath := filepath.Join(config.Path, fileName)

	// 使用 lumberjack 进行日志分割
	logger := &lumberjack.Logger{
		Filename:   logPath,
		MaxSize:    config.MaxSize, // MB
		MaxBackups: config.MaxBackups,
		MaxAge:     config.MaxAge, // days
		Compress:   config.Compress,
	}

	return logger, nil
}

// createSyslogWriter 创建远程syslog writer
func createSyslogWriter(config ZerologSyslogConfig) (io.Writer, error) {
	if config.Network == "" || config.Addr == "" {
		return nil, fmt.Errorf("syslog网络类型或地址不能为空")
	}
	// 连接syslog服务器
	writer, err := syslog.Dial(config.Network, config.Addr, config.Priority, config.Tag)
	if err != nil {
		return nil, err
	}

	return writer, nil
}

// Debug 记录调试日志
func Debug() *zerolog.Event {
	zerologMu.RLock()
	defer zerologMu.RUnlock()
	return zerologInstance.Debug()
}

// Info 记录信息日志
func Info() *zerolog.Event {
	zerologMu.RLock()
	defer zerologMu.RUnlock()
	return zerologInstance.Info()
}

// Warn 记录警告日志
func Warn() *zerolog.Event {
	zerologMu.RLock()
	defer zerologMu.RUnlock()
	return zerologInstance.Warn()
}

// Error 记录错误日志
func Error() *zerolog.Event {
	zerologMu.RLock()
	defer zerologMu.RUnlock()
	return zerologInstance.Error()
}

// Fatal 记录致命错误日志
func Fatal() *zerolog.Event {
	zerologMu.RLock()
	defer zerologMu.RUnlock()
	return zerologInstance.Fatal()
}
