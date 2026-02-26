package main

import (
	"context"
	"crypto/tls"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"net/url"
	"os"
	"regexp"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	tempemail "github.com/XxxXTeam/tempmail-sdk/sdk/go"
)

/*
 * 常量定义
 * @UserAgent 浏览器标识
 * @MaxPollAttempts 邮件轮询最大次数
 * @PollInterval 邮件轮询间隔
 * @MaxRetries 单步骤最大重试次数
 * @KeyFile API Key 保存文件路径
 */
const (
	UserAgent       = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/128.0.0.0 Safari/537.36"
	MaxPollAttempts = 7
	PollInterval    = 3 * time.Second
	MaxRetries      = 3
	KeyFile         = "key.txt"
)

/*
 * 通用请求头，模拟浏览器行为
 */
var commonHeaders = map[string]string{
	"User-Agent":         UserAgent,
	"Accept-Language":    "zh-CN",
	"sec-ch-ua":          `"Not;A=Brand";v="24", "Chromium";v="128"`,
	"sec-ch-ua-platform": `"Windows"`,
	"sec-ch-ua-mobile":   "?0",
}

/*
 * 全局统计计数器
 * @successCount 成功计数
 * @failCount 失败计数
 * @keyMutex 文件写入互斥锁
 * @totalSteps 注册流程总步骤数
 */
var (
	successCount int64
	failCount    int64
	keyMutex     sync.Mutex
)

const totalSteps = 8

/*
 * globalClient 全局复用的 HTTP 客户端
 * @功能 复用连接池，避免每次请求创建新客户端，显著提升并发性能
 */
var globalClient = &http.Client{
	Timeout: 20 * time.Second,
	Transport: &http.Transport{
		TLSClientConfig:     &tls.Config{InsecureSkipVerify: true},
		MaxIdleConns:        100,
		MaxIdleConnsPerHost: 20,
		IdleConnTimeout:     90 * time.Second,
	},
}

/*
 * postForm 发送 POST 表单请求
 * @功能 向指定 URL 发送 application/x-www-form-urlencoded 格式的请求
 * @param reqURL 请求地址
 * @param formData 表单数据
 * @return []byte 响应体
 * @return error 错误信息
 */
func postForm(ctx context.Context, reqURL string, formData url.Values) ([]byte, error) {
	req, err := http.NewRequestWithContext(ctx, "POST", reqURL, strings.NewReader(formData.Encode()))
	if err != nil {
		return nil, fmt.Errorf("创建请求失败: %w", err)
	}

	for k, v := range commonHeaders {
		req.Header.Set(k, v)
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.Header.Set("Origin", "https://passport.mykeeta.com")
	req.Header.Set("Sec-Fetch-Site", "same-site")
	req.Header.Set("Sec-Fetch-Mode", "cors")
	req.Header.Set("Sec-Fetch-Dest", "empty")
	req.Header.Set("Referer", "https://passport.mykeeta.com/")

	resp, err := globalClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("请求失败: %w", err)
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("读取响应失败: %w", err)
	}

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("HTTP %d: %s", resp.StatusCode, string(body))
	}

	return body, nil
}

/*
 * postJSON 发送 POST JSON 请求
 * @功能 向指定 URL 发送 application/json 格式的请求，附带 Cookie
 * @param reqURL 请求地址
 * @param jsonBody JSON 请求体字符串
 * @param token 认证 Token
 * @param referer Referer 头
 * @return []byte 响应体
 * @return error 错误信息
 */
func postJSON(ctx context.Context, reqURL string, jsonBody string, token string, referer string) ([]byte, error) {
	req, err := http.NewRequestWithContext(ctx, "POST", reqURL, strings.NewReader(jsonBody))
	if err != nil {
		return nil, fmt.Errorf("创建请求失败: %w", err)
	}

	for k, v := range commonHeaders {
		req.Header.Set(k, v)
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("x-requested-with", "XMLHttpRequest")
	req.Header.Set("x-client-language", "zh")
	req.Header.Set("Origin", "https://longcat.chat")
	req.Header.Set("Sec-Fetch-Site", "same-origin")
	req.Header.Set("Sec-Fetch-Mode", "cors")
	req.Header.Set("Sec-Fetch-Dest", "empty")
	req.Header.Set("Referer", referer)
	req.Header.Set("Cookie", fmt.Sprintf(
		"passport_token_key=%s; long_cat_region_key=2; com.sankuai.friday.longcat.platform_strategy=",
		token,
	))

	resp, err := globalClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("请求失败: %w", err)
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("读取响应失败: %w", err)
	}

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("HTTP %d: %s", resp.StatusCode, string(body))
	}

	return body, nil
}

/*
 * userRiskCheck 步骤1: 发送邮件开始注册
 * @功能 提交邮箱地址进行风险检查，获取 userTicket
 * @param email 临时邮箱地址
 * @return string userTicket
 * @return error 错误信息
 */
func userRiskCheck(ctx context.Context, email string) (string, error) {
	reqURL := "https://passport-hk.mykeeta.com/api/emaillogin/v1/userriskcheck?uuid=927061b1ab6a41b69f9a.1770185061.1.0.0&lang=en&joinkey=1101498_851697727&token_id=5oTEq210UBLUcm4tcuuy6A&packageNameFilled=false&locale=en&region=HK&cityId=810001&risk_cost_id=119801&yodaReady=h5&csecplatform=4&csecversion=3.4.0"

	formData := url.Values{
		"email":         {email},
		"request_code":  {""},
		"response_code": {""},
	}

	body, err := postForm(ctx, reqURL, formData)
	if err != nil {
		return "", err
	}

	var result struct {
		Data struct {
			UserTicket string `json:"userTicket"`
		} `json:"data"`
	}
	if err := json.Unmarshal(body, &result); err != nil {
		return "", fmt.Errorf("解析响应失败: %w, body: %s", err, string(body))
	}

	if result.Data.UserTicket == "" {
		return "", fmt.Errorf("userTicket 为空, body: %s", string(body))
	}

	return result.Data.UserTicket, nil
}

/*
 * emailSignupApply 步骤2: 获取序列号
 * @功能 使用 userTicket 申请注册，获取邮箱验证码的 serialNumber
 * @param userTicket 用户凭证
 * @return string serialNumber
 * @return error 错误信息
 */
func emailSignupApply(ctx context.Context, userTicket string) (string, error) {
	reqURL := "https://passport-hk.mykeeta.com/api/emaillogin/v1/emailsignupapply?uuid=927061b1ab6a41b69f9a.1770185061.1.0.0&lang=en&joinkey=1101498_851697727&token_id=5oTEq210UBLUcm4tcuuy6A&packageNameFilled=false&locale=en&region=HK&cityId=810001&risk_cost_id=119801&yodaReady=h5&csecplatform=4&csecversion=3.4.0"

	formData := url.Values{
		"username":      {""},
		"user_ticket":   {userTicket},
		"password":      {""},
		"request_code":  {""},
		"response_code": {""},
	}

	body, err := postForm(ctx, reqURL, formData)
	if err != nil {
		return "", err
	}

	var result struct {
		Data struct {
			SerialNumber string `json:"serialNumber"`
		} `json:"data"`
	}
	if err := json.Unmarshal(body, &result); err != nil {
		return "", fmt.Errorf("解析响应失败: %w, body: %s", err, string(body))
	}

	if result.Data.SerialNumber == "" {
		return "", fmt.Errorf("serialNumber 为空, body: %s", string(body))
	}

	return result.Data.SerialNumber, nil
}

/*
 * emailSignup 步骤3: 提交验证码完成注册
 * @功能 使用 userTicket、serialNumber 和邮箱验证码完成注册，获取 token
 * @param userTicket 用户凭证
 * @param serialNumber 序列号
 * @param emailCode 邮箱验证码
 * @return string 登录 token
 * @return error 错误信息
 */
func emailSignup(ctx context.Context, userTicket, serialNumber, emailCode string) (string, error) {
	reqURL := "https://passport-hk.mykeeta.com/api/emaillogin/v1/emailsignup?uuid=927061b1ab6a41b69f9a.1770185061.1.0.0&lang=en&joinkey=1101498_851697727&token_id=5oTEq210UBLUcm4tcuuy6A&packageNameFilled=false&locale=en&region=HK&cityId=810001&risk_cost_id=119801&yodaReady=h5&csecplatform=4&csecversion=3.4.0"

	formData := url.Values{
		"username":           {""},
		"promo_subscription": {"true"},
		"user_ticket":        {userTicket},
		"password":           {""},
		"serial_number":      {serialNumber},
		"email_code":         {emailCode},
		"set_cookie":         {"true"},
	}

	body, err := postForm(ctx, reqURL, formData)
	if err != nil {
		return "", err
	}

	var result struct {
		User struct {
			Token string `json:"token"`
		} `json:"user"`
	}
	if err := json.Unmarshal(body, &result); err != nil {
		return "", fmt.Errorf("解析响应失败: %w, body: %s", err, string(body))
	}

	if result.User.Token == "" {
		return "", fmt.Errorf("token 为空, body: %s", string(body))
	}

	return result.User.Token, nil
}

/*
 * createApiKey 步骤4: 创建 API Key
 * @功能 使用登录 token 创建平台 API Key
 * @param token 登录 token
 * @return string API Key
 * @return error 错误信息
 */
func createApiKey(ctx context.Context, token string) (string, error) {
	reqURL := "https://longcat.chat/api/lc-platform/v1/create-apiKeys"

	body, err := postJSON(ctx, reqURL, `{"name":"03"}`, token, "https://longcat.chat/platform/api_keys")
	if err != nil {
		return "", err
	}

	var result struct {
		Data string `json:"data"`
	}
	if err := json.Unmarshal(body, &result); err != nil {
		return "", fmt.Errorf("解析响应失败: %w, body: %s", err, string(body))
	}

	if result.Data == "" {
		return "", fmt.Errorf("apiKey 为空, body: %s", string(body))
	}

	return result.Data, nil
}

/*
 * addQuotaApproval 步骤5: 发送额度申请通知
 * @功能 使用登录 token 申请使用额度
 * @param token 登录 token
 * @return error 错误信息
 */
func addQuotaApproval(ctx context.Context, token string) error {
	reqURL := "https://longcat.chat/api/lc-platform/v1/addQuotaApproval"
	jsonBody := `{"industry":"其他","company":"","jobRole":"","background":"hi","allowFeedback":true}`

	_, err := postJSON(ctx, reqURL, jsonBody, token, "https://longcat.chat/platform/usage")
	return err
}

/*
 * extractVerificationCode 从邮件内容中提取验证码
 * @功能 使用正则表达式从邮件文本或 HTML 中提取 4-8 位数字验证码
 * @param text 纯文本内容
 * @param html HTML 内容
 * @return string 验证码
 * @return error 错误信息
 */
func extractVerificationCode(text, html string) (string, error) {
	patterns := []*regexp.Regexp{
		regexp.MustCompile(`(?i)(?:verification|verify|code|验证码|驗證碼)[:\s]*(\d{4,8})`),
		regexp.MustCompile(`\b(\d{6})\b`),
		regexp.MustCompile(`\b(\d{4})\b`),
	}

	content := text
	if content == "" {
		content = html
	}

	for _, re := range patterns {
		matches := re.FindStringSubmatch(content)
		if len(matches) > 1 {
			return matches[1], nil
		}
	}

	return "", fmt.Errorf("未找到验证码, 内容: %s", truncate(content, 200))
}

/*
 * truncate 截断字符串
 * @功能 将超长字符串截断到指定长度并附加省略号
 * @param s 原始字符串
 * @param maxLen 最大长度
 * @return string 截断后的字符串
 */
func truncate(s string, maxLen int) string {
	if len(s) <= maxLen {
		return s
	}
	return s[:maxLen] + "..."
}

/*
 * waitForVerificationCode 等待并获取验证码邮件
 * @功能 使用 tempmail-sdk 客户端轮询收件箱，直到获取到包含验证码的邮件
 * @param client tempmail 客户端
 * @return string 验证码
 * @return error 错误信息
 */
func waitForVerificationCode(ctx context.Context, client *tempemail.Client) (string, error) {
	for i := 0; i < MaxPollAttempts; i++ {
		select {
		case <-ctx.Done():
			return "", ctx.Err()
		case <-time.After(PollInterval):
		}

		result, err := client.GetEmails()
		if err != nil {
			continue
		}

		if !result.Success || len(result.Emails) == 0 {
			continue
		}

		for _, email := range result.Emails {
			code, err := extractVerificationCode(email.Text, email.HTML)
			if err == nil {
				return code, nil
			}
		}
	}

	return "", fmt.Errorf("验证码超时")
}

/*
 * withRetry 带重试的函数执行器
 * @功能 执行给定函数，失败时自动重试指定次数
 * @param name 操作名称（用于日志）
 * @param maxRetries 最大重试次数
 * @param fn 要执行的函数
 * @return error 最后一次的错误信息
 */
func withRetry(ctx context.Context, name string, maxRetries int, fn func() error) error {
	var lastErr error
	for i := 0; i <= maxRetries; i++ {
		select {
		case <-ctx.Done():
			return ctx.Err()
		default:
		}
		lastErr = fn()
		if lastErr == nil {
			return nil
		}
		if i < maxRetries {
			select {
			case <-ctx.Done():
				return ctx.Err()
			case <-time.After(time.Duration(i+1) * 2 * time.Second):
			}
		}
	}
	return fmt.Errorf("%s: %w", name, lastErr)
}

/*
 * saveKey 保存 API Key 到文件
 * @功能 线程安全地将 API Key 追加写入 key.txt
 * @param key API Key 字符串
 */
func saveKey(key string) {
	keyMutex.Lock()
	defer keyMutex.Unlock()

	f, err := os.OpenFile(KeyFile, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0644)
	if err != nil {
		return
	}
	defer f.Close()
	f.WriteString(key + "\n")
}

/*
 * runRound 执行一轮完整的注册流程
 * @功能 生成临时邮箱 → 风险检查 → 申请注册 → 获取验证码 → 完成注册 → 创建 API Key → 申请额度
 * @param workerID 工作线程编号
 * @param channel 指定的邮箱渠道（为空则随机）
 * @return error 错误信息
 */
func runRound(ctx context.Context, channel tempemail.Channel) (string, error) {
	/* 步骤1: 生成临时邮箱 */
	select {
	case <-ctx.Done():
		return "", ctx.Err()
	default:
	}
	client := tempemail.NewClient()
	opts := &tempemail.GenerateEmailOptions{}
	if channel != "" {
		opts.Channel = channel
	}

	emailInfo, err := client.Generate(opts)
	if err != nil {
		return "", fmt.Errorf("邮箱: %w", err)
	}
	if emailInfo == nil {
		return "", fmt.Errorf("邮箱: 所有渠道不可用")
	}

	/* 步骤2: 风险检查 */
	var userTicket string
	err = withRetry(ctx, "风险检查", MaxRetries, func() error {
		var e error
		userTicket, e = userRiskCheck(ctx, emailInfo.Email)
		return e
	})
	if err != nil {
		return "", err
	}

	/* 步骤3: 获取序列号 */
	var serialNumber string
	err = withRetry(ctx, "序列号", MaxRetries, func() error {
		var e error
		serialNumber, e = emailSignupApply(ctx, userTicket)
		return e
	})
	if err != nil {
		return "", err
	}

	/* 步骤4: 等待验证码 */
	var emailCode string
	err = withRetry(ctx, "验证码", 1, func() error {
		var e error
		emailCode, e = waitForVerificationCode(ctx, client)
		return e
	})
	if err != nil {
		return "", err
	}

	/* 步骤5: 提交注册 */
	var token string
	err = withRetry(ctx, "注册", MaxRetries, func() error {
		var e error
		token, e = emailSignup(ctx, userTicket, serialNumber, emailCode)
		return e
	})
	if err != nil {
		return "", err
	}

	/* 步骤6: 创建 API Key */
	var apiKey string
	err = withRetry(ctx, "创建 Key", MaxRetries, func() error {
		var e error
		apiKey, e = createApiKey(ctx, token)
		return e
	})
	if err != nil {
		return "", err
	}

	/* 步骤7: 额度申请（失败不影响） */
	withRetry(ctx, "额度", MaxRetries, func() error {
		return addQuotaApproval(ctx, token)
	})

	/* 步骤8: 保存 Key */
	saveKey(apiKey)

	return apiKey, nil
}

/*
 * worker 工作线程
 * @功能 从任务通道中获取任务并执行注册流程，支持失败自动重试
 * @param workerID 工作线程编号
 * @param tasks 任务通道
 * @param wg 等待组
 * @param target 目标数量
 * @param maxRoundRetries 单轮最大重试次数
 * @param channel 指定的邮箱渠道
 */
func worker(ctx context.Context, cancel context.CancelFunc, workerID int, wg *sync.WaitGroup, target *int64, maxRoundRetries int, channel tempemail.Channel) {
	defer wg.Done()
	log := slog.Default().With("W", fmt.Sprintf("%s#%d%s", colorPurple, workerID, colorReset))

	for {
		/* 检查目标和上下文 */
		if atomic.LoadInt64(target) <= 0 {
			return
		}
		select {
		case <-ctx.Done():
			return
		default:
		}

		var apiKey string
		var lastErr error
		for retry := 0; retry <= maxRoundRetries; retry++ {
			if retry > 0 {
				select {
				case <-ctx.Done():
					return
				case <-time.After(time.Duration(retry) * 3 * time.Second):
				}
			}
			apiKey, lastErr = runRound(ctx, channel)
			if lastErr == nil {
				break
			}
			/* 如果是 context 取消导致的失败，直接退出 */
			if ctx.Err() != nil {
				return
			}
		}

		if lastErr == nil {
			sc := atomic.AddInt64(&successCount, 1)
			remaining := atomic.AddInt64(target, -1)
			log.Info(fmt.Sprintf("%s%s✓%s %s%s%s %s(%d完成)%s",
				colorBold, colorGreen, colorReset,
				colorCyan, apiKey, colorReset,
				colorDim, sc, colorReset))
			/* 目标达成，取消所有在途 worker */
			if remaining <= 0 {
				cancel()
				return
			}
		} else {
			atomic.AddInt64(&failCount, 1)
			log.Error(fmt.Sprintf("失败 %s%s%s",
				colorDim, truncate(lastErr.Error(), 60), colorReset))
		}
	}
}

func main() {
	/*
	 * 命令行参数定义
	 * @param threads 并发线程数，默认 1
	 * @param count 目标获取数量，默认 1
	 * @param retries 单轮整体重试次数，默认 3
	 * @param channel 指定邮箱渠道，默认随机
	 * @param verbose 是否输出调试日志
	 */
	threads := flag.Int("threads", 1, "并发线程数")
	count := flag.Int("count", 1, "目标获取 Key 数量")
	retries := flag.Int("retries", 3, "单轮失败重试次数")
	channelName := flag.String("channel", "", "指定邮箱渠道（留空随机选择）")
	verbose := flag.Bool("v", false, "显示调试日志")
	flag.Parse()

	/* 初始化彩色日志 */
	logLevel := slog.LevelInfo
	if *verbose {
		logLevel = slog.LevelDebug
	}
	handler := NewColorHandler(os.Stdout)
	logger := slog.New(&levelFilter{handler: handler, level: logLevel})
	slog.SetDefault(logger)

	var channel tempemail.Channel
	if *channelName != "" {
		channel = tempemail.Channel(*channelName)
	}

	printBanner(*threads, *count, *retries, *channelName)

	startTime := time.Now()

	/* 设置 tempmail-sdk 跳过 SSL 验证 */
	tempemail.SetConfig(tempemail.SDKConfig{Insecure: true})

	/* 创建全局 context，目标达成后 cancel 终止所有 worker */
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	/* 启动工作线程，每个 worker 自己循环直到 target=0 或 ctx 取消 */
	remaining := int64(*count)
	var wg sync.WaitGroup
	for i := 1; i <= *threads; i++ {
		wg.Add(1)
		go worker(ctx, cancel, i, &wg, &remaining, *retries, channel)
	}

	wg.Wait()

	elapsed := time.Since(startTime)
	printSummary(atomic.LoadInt64(&successCount), atomic.LoadInt64(&failCount), elapsed)
}

/*
 * levelFilter 日志级别过滤器
 * @功能 包装 slog.Handler，只允许指定级别及以上的日志输出
 * @field handler 被包装的处理器
 * @field level 最低日志级别
 */
type levelFilter struct {
	handler slog.Handler
	level   slog.Level
}

func (f *levelFilter) Enabled(_ context.Context, level slog.Level) bool {
	return level >= f.level
}

func (f *levelFilter) Handle(ctx context.Context, r slog.Record) error {
	return f.handler.Handle(ctx, r)
}

func (f *levelFilter) WithAttrs(attrs []slog.Attr) slog.Handler {
	return &levelFilter{handler: f.handler.WithAttrs(attrs), level: f.level}
}

func (f *levelFilter) WithGroup(name string) slog.Handler {
	return &levelFilter{handler: f.handler.WithGroup(name), level: f.level}
}
