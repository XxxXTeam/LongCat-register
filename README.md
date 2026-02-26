# LongCat-register

一个自动化注册 LongCat AI 平台账号并获取 API Key 的 Go 语言工具。

## 功能特性

- **自动化注册流程**：自动生成临时邮箱，完成风险检查、验证码获取、账号注册全流程
- **API Key 获取**：自动创建 LongCat 平台 API Key 并保存到文件
- **额度申请**：自动提交使用额度申请
- **多线程并发**：支持多线程并发注册，提高效率
- **自动重试机制**：每个步骤失败自动重试，提高成功率
- **彩色日志输出**：美观的终端输出，实时显示进度

## 安装

### 前置要求

- Go 1.21 或更高版本

### 从源码编译

```bash
# 克隆仓库
git clone https://github.com/XxxXTeam/LongCat-register
cd LongCat-register

# 下载依赖
go mod tidy

# 编译
go build 
```

## 使用方法

### 基本用法

```bash
# 获取 1 个 API Key（默认单线程）
./longcat-register

# 获取 10 个 API Key，使用 5 个线程
./longcat-register -count 10 -threads 5

# 显示调试日志
./longcat-register -v
```

### 命令行参数

| 参数 | 默认值 | 说明 |
|------|--------|------|
| `-count` | 1 | 目标获取 Key 数量 |
| `-threads` | 1 | 并发线程数 |
| `-retries` | 3 | 单轮失败重试次数 |
| `-channel` | "" | 指定邮箱渠道（留空随机选择） |
| `-v` | false | 显示调试日志 |

### 示例

```bash
# 使用 10 线程获取 50 个 Key，开启调试模式
./longcat-register -threads 10 -count 50 -v

# 指定邮箱渠道获取 5 个 Key
./longcat-register -count 5 -channel "tempmail"
```

## 输出文件

- **key.txt**: 成功获取的 API Key 列表，每行一个

## 注册流程

1. **生成临时邮箱** - 使用 tempmail-sdk 生成临时邮箱地址
2. **风险检查** - 向 passport 服务提交邮箱进行风险检查
3. **申请注册** - 获取邮箱验证码的序列号
4. **等待验证码** - 轮询收件箱获取验证码邮件
5. **提交注册** - 使用验证码完成账号注册
6. **创建 API Key** - 在平台创建 API Key
7. **申请额度** - 提交使用额度申请（失败不影响结果）
8. **保存 Key** - 将 API Key 保存到文件

## 项目结构

```
.
├── main.go      # 主程序逻辑，包含注册流程实现
├── logger.go    # 彩色日志处理器
├── go.mod       # Go 模块定义
├── go.sum       # Go 依赖校验
└── key.txt      # 输出的 API Key 文件（运行时生成）
```

## 技术栈

- **Go 1.25.5** - 编程语言
- **tempmail-sdk** - 临时邮箱服务 SDK
- **slog** - 结构化日志库

## 注意事项

1. 本工具仅供学习和测试使用
2. 请遵守 LongCat 平台的使用条款
3. 过度使用可能导致 IP 被封禁
4. 临时邮箱服务可能不稳定，失败时可增加重试次数

## 许可证

[GNU General Public License v3.0 (GPL-3.0)](https://www.gnu.org/licenses/gpl-3.0.html)

本程序是自由软件：你可以再发布本程序和/或修改本程序，但必须遵守 GNU 通用公共许可证的条款，无论是第三版还是（根据你的选择）任何后续版本。

本程序发布的目的是希望它有用，但**没有任何担保**。甚至没有适合特定目的的隐含担保。更多细节请参见 GNU 通用公共许可证。

你应该已经随本程序收到了一份 GNU 通用公共许可证的副本。如果没有，请参阅 <https://www.gnu.org/licenses/>。
