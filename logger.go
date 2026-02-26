package main

import (
	"context"
	"fmt"
	"io"
	"log/slog"
	"sync"
	"time"
)

/*
 * ANSI 终端颜色代码常量
 * @功能 用于日志输出的颜色美化
 */
const (
	colorReset  = "\033[0m"
	colorRed    = "\033[31m"
	colorGreen  = "\033[32m"
	colorYellow = "\033[33m"
	colorBlue   = "\033[34m"
	colorPurple = "\033[35m"
	colorCyan   = "\033[36m"
	colorGray   = "\033[37m"
	colorWhite  = "\033[97m"
	colorBold   = "\033[1m"
	colorDim    = "\033[2m"

	colorBgGreen  = "\033[42m"
	colorBgRed    = "\033[41m"
	colorBgYellow = "\033[43m"
	colorBgBlue   = "\033[44m"
	colorBgCyan   = "\033[46m"
)

/*
 * ColorHandler 自定义彩色日志处理器
 * @功能 实现 slog.Handler 接口，输出带颜色和图标的格式化日志
 * @field w 输出目标
 * @field mu 写入互斥锁
 * @field attrs 附加属性
 * @field group 日志分组前缀
 */
type ColorHandler struct {
	w     io.Writer
	mu    *sync.Mutex
	attrs []slog.Attr
	group string
}

/*
 * NewColorHandler 创建彩色日志处理器
 * @param w 输出目标（如 os.Stdout）
 * @return *ColorHandler 处理器实例
 */
func NewColorHandler(w io.Writer) *ColorHandler {
	return &ColorHandler{
		w:  w,
		mu: &sync.Mutex{},
	}
}

/*
 * Enabled 判断日志级别是否启用
 * @param ctx 上下文
 * @param level 日志级别
 * @return bool 始终返回 true
 */
func (h *ColorHandler) Enabled(_ context.Context, _ slog.Level) bool {
	return true
}

/*
 * levelIcon 获取日志级别对应的图标和颜色
 * @param level 日志级别
 * @return string 图标
 * @return string 颜色代码
 * @return string 级别标签
 */
func levelIcon(level slog.Level) (string, string, string) {
	switch {
	case level >= slog.LevelError:
		return "✗", colorRed, "ERR"
	case level >= slog.LevelWarn:
		return "!", colorYellow, "WRN"
	case level >= slog.LevelInfo:
		return "→", colorGreen, "INF"
	default:
		return "·", colorGray, "DBG"
	}
}

/*
 * Handle 处理日志记录，格式化为彩色输出
 * @功能 将日志记录格式化为: 时间 图标 [级别] 消息 key=value ...
 * @param ctx 上下文
 * @param r 日志记录
 * @return error 错误信息
 */
func (h *ColorHandler) Handle(_ context.Context, r slog.Record) error {
	icon, color, _ := levelIcon(r.Level)

	timeStr := r.Time.Format("15:04:05")

	/* 构建属性字符串 */
	attrStr := ""
	writeAttr := func(a slog.Attr) {
		if a.Key == "" {
			return
		}
		key := a.Key
		if h.group != "" {
			key = h.group + "." + key
		}
		attrStr += fmt.Sprintf(" %s%s%s=%s%v%s",
			colorDim, key, colorReset,
			colorWhite, a.Value.Any(), colorReset,
		)
	}

	for _, a := range h.attrs {
		writeAttr(a)
	}
	r.Attrs(func(a slog.Attr) bool {
		writeAttr(a)
		return true
	})

	line := fmt.Sprintf("%s%s%s %s%s%s %s%s%s%s\n",
		colorDim, timeStr, colorReset,
		color, icon, colorReset,
		colorWhite, r.Message, colorReset,
		attrStr,
	)

	h.mu.Lock()
	defer h.mu.Unlock()
	_, err := fmt.Fprint(h.w, line)
	return err
}

/*
 * WithAttrs 创建携带额外属性的处理器副本
 * @param attrs 附加属性列表
 * @return slog.Handler 新的处理器实例
 */
func (h *ColorHandler) WithAttrs(attrs []slog.Attr) slog.Handler {
	newAttrs := make([]slog.Attr, len(h.attrs)+len(attrs))
	copy(newAttrs, h.attrs)
	copy(newAttrs[len(h.attrs):], attrs)
	return &ColorHandler{
		w:     h.w,
		mu:    h.mu,
		attrs: newAttrs,
		group: h.group,
	}
}

/*
 * WithGroup 创建带分组前缀的处理器副本
 * @param name 分组名称
 * @return slog.Handler 新的处理器实例
 */
func (h *ColorHandler) WithGroup(name string) slog.Handler {
	g := name
	if h.group != "" {
		g = h.group + "." + name
	}
	return &ColorHandler{
		w:     h.w,
		mu:    h.mu,
		attrs: h.attrs,
		group: g,
	}
}

func printBanner(threads, count, retries int, channel string) {
}

/*
 * printSummary 打印任务结束汇总
 * @功能 在终端输出带颜色的执行结果统计
 * @param success 成功数量
 * @param fail 失败数量
 * @param elapsed 耗时
 */
func printSummary(success, fail int64, elapsed time.Duration) {
	fmt.Printf("  %s▸ 成  功%s  %s%s%d%s\n", colorGray, colorReset, colorBold, colorGreen, success, colorReset)
	fmt.Printf("  %s▸ 失  败%s  %s%s%d%s\n", colorGray, colorReset, colorBold, colorRed, fail, colorReset)
	fmt.Printf("  %s▸ 耗  时%s  %s%v%s\n", colorGray, colorReset, colorWhite, elapsed.Round(time.Second), colorReset)
}

/*
 * stepLog 输出步骤进度日志（DEBUG 级别）
 * @功能 格式化输出当前步骤的进度信息（带进度条和颜色），仅在 -v 模式显示
 * @param log slog.Logger 实例
 * @param step 步骤编号（1-8）
 * @param total 总步骤数
 * @param msg 步骤描述
 */
func stepLog(log *slog.Logger, step, total int, msg string) {
	bar := ""
	for i := 1; i <= total; i++ {
		if i <= step {
			bar += fmt.Sprintf("%s█%s", colorCyan, colorReset)
		} else {
			bar += fmt.Sprintf("%s░%s", colorGray, colorReset)
		}
	}
	log.Debug(fmt.Sprintf("%s[%d/%d]%s %s %s", colorDim, step, total, colorReset, bar, msg))
}

/*
 * progressStr 生成紧凑的进度条字符串
 * @功能 生成如 [3/8] 的进度标签，带颜色
 * @param step 当前步骤
 * @param total 总步骤数
 * @return string 格式化的进度字符串
 */
func progressStr(step, total int) string {
	return fmt.Sprintf("%s[%d/%d]%s", colorDim, step, total, colorReset)
}
