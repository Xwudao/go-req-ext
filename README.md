# go-req-ext

[`go-req`](https://github.com/Xwudao/go-req) 的扩展包集合。

一个仓库，多个 Go module，按需引入。轻量扩展保持标准库优先；浏览器指纹等重依赖能力放在独立子模块中，**只使用 Cookie 管理的项目不会下载、编译或链接 Chrome/Firefox/Safari 指纹模拟代码**。

> 从 `go-req-impersonate` 迁移：浏览器指纹的引入路径已变为 `github.com/Xwudao/go-req-ext/impersonate`。旧仓库保留历史，不再更新。

## 模块布局

| 模块 | 引入路径 | 依赖 | 内容 |
| --- | --- | --- | --- |
| `github.com/Xwudao/go-req-ext` | `.../jar`、`.../persist` | 仅标准库 | Cookie 管理、持久化存储 |
| `github.com/Xwudao/go-req-ext/impersonate` | `.../impersonate` | uTLS、fhttp、tls-client | 浏览器 TLS / HTTP2 指纹 |

```text
go-req-ext/
├── go.mod                 # 轻量模块：零第三方依赖（Go 1.21+）
├── go.work                # 本地开发用 workspace
├── jar/                   # http.CookieJar + 持久化
├── persist/               # Store 接口、Memory、File
└── impersonate/           # 独立 module（Go 1.24.1+）
    ├── go.mod
    └── ...
```

`impersonate/` 有自己的 `go.mod`，因此根模块的依赖图不包含它。Go 的链接器本来就只打包被 import 的包；嵌套 module 进一步保证 `go get .../jar` 不会把指纹依赖写进你的依赖图。

## 安装

Cookie 管理与持久化（零第三方依赖）：

```bash
go get github.com/Xwudao/go-req-ext/jar
go get github.com/Xwudao/go-req-ext/persist
```

浏览器指纹（显式安装独立子模块）：

```bash
go get github.com/Xwudao/go-req-ext/impersonate
```

## jar：Cookie 管理

`jar.Jar` 实现标准库 `http.CookieJar`，可直接交给 `http.Client` 或 `go-req`。

```go
package main

import (
	"context"
	"net/http"
	"time"

	"github.com/Xwudao/go-req"
	"github.com/Xwudao/go-req-ext/jar"
	"github.com/Xwudao/go-req-ext/persist"
)

func main() {
	ctx := context.Background()

	store := persist.NewFile("cookies.json")
	j, err := jar.Open(ctx,
		jar.WithStore(store),
		jar.WithAutoSave(2*time.Second),
	)
	if err != nil {
		panic(err)
	}
	defer j.Close() // 停止自动保存并做最后一次落盘

	client := req.New(req.WithHTTPClient(&http.Client{Jar: j}))
	_ = client
}
```

标准库用法：

```go
client := &http.Client{Jar: j}
```

已实现的行为：

- host-only / Domain Cookie，Domain 与 Path 匹配
- `Secure`：HTTPS 下发、HTTPS 回传
- `Expires`、`Max-Age`，以及 `MaxAge < 0` 删除
- 读取时惰性清理过期 Cookie
- RFC 6265 排序：Path 越长越靠前，其次按创建时间
- 并发安全
- `Snapshot` / `Restore`、`Clear`
- JSON 持久化，可选防抖自动保存
- 可注入 `cookiejar.PublicSuffixList`（例如 `golang.org/x/net/publicsuffix.List`）拒绝公共后缀 Cookie；不注入时只做语法级域名校验

`jar` 不读取环境变量、不做网络 I/O，也不会自动导入指纹模块。

## persist：持久化存储

`persist.Store` 是一个最小的字节存储接口：

```go
type Store interface {
	Load(ctx context.Context) ([]byte, error)
	Save(ctx context.Context, data []byte) error
	Delete(ctx context.Context) error
}
```

内置实现：

- `persist.NewMemory()`：进程内存储，适合测试
- `persist.NewFile(path)`：原子写入（临时文件 + rename），默认文件权限 `0600`、目录权限 `0700`

`persist.LoadJSON` / `persist.SaveJSON` 提供 JSON 便捷封装。缺少数据时返回 `persist.ErrNotExist`。

## impersonate：浏览器指纹

`impersonate` 是独立 module，提供标准库 `http.RoundTripper`：

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
```

支持 Chrome / Firefox / Safari 快照、HTTP/HTTPS/SOCKS5 代理、自定义 Header 顺序。详细边界与配置见 [`impersonate/README.md`](impersonate/README.md)。

## 版本与发布

两个 module 独立打 tag：

```bash
# 根模块：jar、persist
git tag v0.1.0

# 子模块：impersonate
git tag impersonate/v0.1.0
```

引用子模块：

```bash
go get github.com/Xwudao/go-req-ext/impersonate@v0.1.0
```

## 开发

仓库根目录包含 `go.work`，可一次测试所有模块：

```bash
go test ./... ./impersonate/...
```

也可以按模块隔离测试（CI 使用这种方式，以验证根模块的零依赖约束）：

```bash
GOWORK=off go test ./...                 # 根模块，Go 1.21+
cd impersonate && GOWORK=off go test ./...  # 指纹模块，Go 1.24.1+
```

新增扩展时的依赖规则：

1. 只依赖标准库的包放在根模块，例如 `jar`、`persist`。
2. 引入第三方依赖或体积较大的包，放在自己的嵌套 module 中（参考 `impersonate/`）。
3. 根模块不得 import 任何嵌套 module，保证轻量用户不会被动链接重依赖。

## 许可

本仓库自身代码只做适配与编排。`impersonate` 的协议能力来自上游依赖，发布或再分发前请复核：

- `bogdanfinn/tls-client`：BSD-4-Clause（含广告条款）
- `refraction-networking/utls`：BSD-3-Clause
- `bogdanfinn/fhttp`
- `bogdanfinn/utls`
