# go-req-ext / impersonate

`impersonate`（package `impersonate`）是 [`go-req`](https://github.com/Xwudao/go-req) 的可选浏览器指纹扩展模块，属于 [`go-req-ext`](../README.md) 多模块仓库。

> **模块隔离**：本目录是独立的 Go module。只使用 `jar`、`persist` 等项目时，不会下载、编译或链接本模块，也不会把 uTLS、fhttp、tls-client 和 Chrome/Firefox/Safari Profile 数据带进最终二进制。使用指纹能力需要显式 `go get github.com/Xwudao/go-req-ext/impersonate` 并 import 本包。

它提供一个标准库 `http.RoundTripper`，用于模拟特定浏览器快照的 TLS ClientHello、ALPN 和 HTTP/2 行为。核心 `go-req` 不依赖 uTLS、tls-client 或 fhttp，也不需要为了指纹功能修改自身：

```go
transport, err := impersonate.New(
    impersonate.Chrome(),
    impersonate.WithProxy("http://127.0.0.1:7890"),
)
if err != nil {
    return err
}

client := req.New(
    req.WithTransport(transport),
)
```

也可以直接交给标准库：

```go
httpClient := &http.Client{Transport: transport}
```

> **重要边界**：指纹模拟不等于完整浏览器环境。它只模拟选定的 TLS/HTTP2 网络特征，不模拟 JavaScript、Canvas、WebGL、Cookie 行为、请求头语义或浏览器版本信息，也不保证绕过任何网站的检测。

## 为什么是独立模块

核心 `go-req` 保持“只依赖标准库”的设计原则，`go-req-ext` 也按依赖边界拆分模块：

- `github.com/Xwudao/go-req-ext`：`jar`、`persist` 等轻量扩展，零第三方依赖。
- `github.com/Xwudao/go-req-ext/impersonate`：本模块，独立维护 uTLS/fhttp/tls-client 等较重依赖。

这样，一个只需要 Cookie 管理的应用不会因为同仓库存在指纹模块而增加依赖图、下载体积或二进制体积。本模块自身维护的第三方依赖：

- `refraction-networking/utls` / `bogdanfinn/utls`：TLS ClientHello 构造
- `bogdanfinn/fhttp`：可配置 HTTP/2 SETTINGS、优先级、Header 顺序的 HTTP 协议栈
- `bogdanfinn/tls-client`：成熟浏览器 Profile 数据（ClientHello + HTTP/2 参数）
- `golang.org/x/net/proxy`：SOCKS5 客户端

`go-req` 核心只看到一个普通 `http.RoundTripper`。

## 调研结论（2026-10 当前 API）

| 项目 | 当前版本 | 维护状态 | 能力与定位 | 本模块使用方式 |
| --- | --- | --- | --- | --- |
| `refraction-networking/utls` | v1.8.2 | 活跃，BSD-3-Clause | 提供 `ClientHelloID`、`UClient`、ClientHello 指纹解析；只负责 TLS，不提供 HTTP/2 指纹 | 调研参考；实际使用 tls-client 依赖的 uTLS fork |
| `bogdanfinn/tls-client` | v1.16.0 | 活跃，BSD-4-Clause | 高层 `HttpClient`，基于 fhttp + uTLS，提供大量 Chrome/Firefox/Safari Profile、代理、HTTP/2/3 | 复用其浏览器 Profile 表；不使用其高层客户端 |
| `bogdanfinn/fhttp` | v0.6.9 | 活跃 | `net/http` fork，暴露 HTTP/2 SETTINGS、优先级、Pseudo Header 顺序、普通 Header 顺序 | 作为底层 HTTP/1、HTTP/2 协议栈 |

选择方案：

- **不复用 tls-client 的 `HttpClient` 作为最终适配层**，因为它内部使用 fhttp 请求/响应类型，且把请求生命周期超时、代理和 fhttp Transport 绑定在一起；直接包装会引入额外超时语义和代理 TLS 限制。
- **复用 tls-client 的 Profile 数据**，避免自己维护浏览器 TLS/HTTP2 指纹参数。
- **复用 fhttp 的 HTTP/1 与 HTTP/2 实现**，不自行编写 TLS 或 HTTP/2 协议栈。
- 自行实现约一层薄的 stdlib ↔ fhttp 类型适配、代理拨号和按地址缓存 Transport，从而保留标准库语义、Context、流式 Body 和资源生命周期控制。

## 安装

要求 Go 1.27 或更高版本（与 go-req v0.2.0 一致）。

```bash
go get github.com/Xwudao/go-req-ext/impersonate
```

```go
import "github.com/Xwudao/go-req-ext/impersonate"
```

package 名是 `impersonate`。

## Profile

```go
impersonate.Chrome()   // 当前映射到具体快照 chrome_150
impersonate.Firefox()  // 当前映射到具体快照 firefox_147
impersonate.Safari()   // 当前映射到桌面快照 safari_16_0
```

指定版本：

```go
chrome131, err := impersonate.ChromeVersion("131")
firefox147, err := impersonate.FirefoxVersion("147")
safari16, err := impersonate.SafariVersion("16.0")
```

按上游名称选择任意 Profile：

```go
profile, err := impersonate.ProfileByName("safari_ios_26_0")
```

列出全部可用快照：

```go
for _, name := range impersonate.Profiles() {
    fmt.Println(name)
}
```

高级自定义（使用 tls-client 的 `profiles.NewClientProfile`）：

```go
custom, err := impersonate.NewProfile("my-profile", clientProfile)
```

### 版本声明

- `Chrome()` 返回一个**固定 Chrome 快照**，不是“所有 Chrome 版本”的精确指纹。
- 浏览器小版本、平台、实验特性、GREASE、ECH、ALPS、扩展顺序等都可能变化。
- 如果站点依赖精确版本特征，应选择明确版本的 Profile，并自行持续验证。
- 同理，`Firefox()`、`Safari()` 也是快照，不是版本范围的承诺。

## 配置

```go
transport, err := impersonate.New(
    impersonate.Chrome(),
    impersonate.WithProxy("http://user:password@127.0.0.1:7890"),
    impersonate.WithHeaderOrder("user-agent", "accept", "accept-language"),
    impersonate.WithIdleConnTimeout(90*time.Second),
    impersonate.WithHandshakeTimeout(15*time.Second),
)
```

| Option | 行为 |
| --- | --- |
| `WithProxy(rawURL)` | 设置显式代理；支持 `http`、`https`、`socks5`、`socks5h` 和 URL 用户名密码 |
| `WithRootCAs(pool)` | 设置 HTTPS 目标与 HTTPS 代理的根证书 |
| `WithInsecureSkipVerify()` | 关闭证书校验；仅建议受控测试使用 |
| `WithHeaderOrder(names...)` | 覆盖 Profile 默认普通 Header 顺序；传空表示关闭自动排序 |
| `WithIdleConnTimeout(d)` | HTTP/1、HTTP/2 空闲连接超时；0 表示不限 |
| `WithHandshakeTimeout(d)` | 无请求 Context 的新 HTTP/2 连接握手超时；默认 15s |

代理地址会校验 Scheme、Host 和端口：

- HTTP/HTTPS 省略端口时分别使用 80/443
- SOCKS5/SOCKS5h 必须显式指定端口
- 拒绝相对地址、空主机、无效端口、path、query、fragment

## 代理支持边界

| 代理类型 | 支持 | 说明 |
| --- | --- | --- |
| HTTP 代理 | 是 | 对 HTTP 和 HTTPS 目标都使用 `CONNECT` 隧道；代理必须允许 CONNECT 到目标端口（包括 HTTP 的 80） |
| HTTPS 代理 | 是 | 先与代理建立 TLS，再发送 CONNECT；代理证书使用系统根、`WithRootCAs` 或 `WithInsecureSkipVerify` |
| SOCKS5 | 是 | 使用 `golang.org/x/net/proxy`；支持无认证和用户名密码认证 |
| SOCKS5h | 是 | 当前 x/net/proxy 会把域名交给代理解析，因此 `socks5` 与 `socks5h` 都表现为远端 DNS |
| 环境变量代理 | 否 | 本模块不会隐式读取 `HTTP_PROXY`/`HTTPS_PROXY`；需要显式 `WithProxy` |
| SOCKS4 / HTTP/3 / UDP | 否 | 不在本模块支持范围 |

注意：HTTP 代理采用 CONNECT 隧道，而不是 absolute-form 普通 HTTP 转发。只支持 absolute-form、不允许 CONNECT 80 端口的代理不适用于本模块。

代理配置与核心 `go-req` 冲突时不会静默忽略：

```go
_, err := req.NewWithOptions(
    req.WithTransport(transport),              // 插件 Transport 是自定义 RoundTripper
    req.WithProxy("http://127.0.0.1:7890"),    // 核心会返回 ErrConfiguration
)
```

同理，`req.WithTransport(transport)` 与 `req.WithDialContext(...)` 组合也会由核心显式报错。插件自己的代理配置应通过 `impersonate.WithProxy` 完成。

## 标准库语义

- `Transport` 实现标准 `http.RoundTripper`，`RoundTrip` 不处理重定向。
- 请求和响应类型始终是标准库 `*http.Request` / `*http.Response`；fhttp 类型只存在于内部适配层。
- 请求 Body 和响应 Body 不做全量缓冲，响应保持流式读取。
- `Body.Close`、Context 取消、Deadline、`http.Client.Timeout` 和 `req.WithTimeout` 继续生效。
- 响应 `Trailer` 在 Body 读完后同步到标准库 Response。
- `Response.TLS` 从 uTLS 连接状态转换为 `crypto/tls.ConnectionState`。
- `CloseIdleConnections()` 关闭所有缓存的 HTTP/1/HTTP/2 空闲连接；调用后 Transport 仍可继续使用。
- Transport 并发安全；每个目标地址的 Transport 缓存在互斥锁保护下创建。
- 首次 HTTPS 请求使用请求 Context 进行 ALPN 探测；fhttp HTTP/2 的后续新连接没有 Context 参数，因此使用 `WithHandshakeTimeout`（默认 15s）作为握手上限。
- `go-req` 的 Debug 可以正常包装该 Transport；Debug 逻辑仍位于核心库，不会记录代理用户名、密码。

## 指纹验证

测试不只检查 User-Agent。当前测试使用本地服务器验证实际线上特征：

1. **TLS ClientHello**
   - 原始 TCP 服务器捕获 ClientHello 字节
   - 使用 uTLS 解析为 `ClientHelloSpec`
   - 对比 Cipher Suites、Extension 类型与顺序、Supported Curves、Supported Versions、Signature Algorithms、ALPN、Compression Methods
   - Chrome、Firefox、Safari 快照均覆盖

2. **HTTP/2**
   - 本地 TLS 服务器协商 ALPN `h2`
   - 直接读取 HTTP/2 帧
   - 对比 SETTINGS ID 顺序和值、连接级 WINDOW_UPDATE、Pseudo Header 顺序、普通 Header 顺序
   - 验证实际响应 Body 与 `Response.ProtoMajor == 2`

3. **代理**
   - 本地 HTTP CONNECT 代理
   - 本地 HTTPS CONNECT 代理
   - 本地 SOCKS5 代理（含用户名密码）
   - 认证、HTTP 目标、HTTPS 目标、HTTP/2 目标

运行：

```bash
go test ./...
go test -race ./...
go vet ./...
```

## 使用示例

### 固定 Chrome + HTTP 代理

```go
transport, err := impersonate.New(
    impersonate.Chrome(),
    impersonate.WithProxy("http://127.0.0.1:7890"),
)
if err != nil {
    return err
}
defer transport.CloseIdleConnections()

client := req.New(req.WithTransport(transport))

var out map[string]any
err = client.Get(ctx, "https://example.com/api").ToJSON(&out)
```

### 使用指定 Chrome 版本

```go
chrome, err := impersonate.ChromeVersion("131")
if err != nil {
    return err
}

transport, err := impersonate.New(chrome)
if err != nil {
    return err
}
```

### 标准库 http.Client

```go
transport, err := impersonate.New(impersonate.Firefox())
if err != nil {
    return err
}
defer transport.CloseIdleConnections()

client := &http.Client{
    Transport: transport,
    Timeout:   30 * time.Second,
}
```

## 设计边界

- 不提供 `ProxyManager`、浏览器管理器或每个请求自动切换 Profile 的 DSL。
- 每个 Transport 固定一个 Profile；需要不同 Profile 时创建多个 Transport。
- 不修改 `http.DefaultTransport`、`http.DefaultClient` 或调用方传入的 Transport。
- 不尝试模拟浏览器应用层行为。
- 不承诺任何站点检测规避效果。

## 依赖与许可提示

本模块自身只做适配与编排，实际协议能力来自上游依赖。发布或再分发前请复核依赖许可证：

- `bogdanfinn/tls-client`：BSD-4-Clause（含广告条款）
- `refraction-networking/utls`：BSD-3-Clause
- `bogdanfinn/fhttp`：GitHub 在调研时未返回仓库级 license 元数据；源码源自 Go `net/http` 的 BSD 风格实现，使用前请自行复核
- `bogdanfinn/utls`：tls-client 使用的 uTLS fork

综上，指纹模拟是网络层近似，不是浏览器自动化，也不是绕过检测的保证。
