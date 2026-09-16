# Banner 指纹识别系统

使用 Go 分析网络扫描得到的 `ip、port、banner`，返回协议、软件、版本、系统提示和置信度。适用于资产盘点和扫描结果整理。例如，`SSH-2.0-OpenSSH_8.9p1 Ubuntu-3` 会被识别为 SSH / OpenSSH / 8.9p1 / Ubuntu。

当前是可运行的初始化基础版本，包含 server、独立 client、外部规则、示例数据、测试和 Docker Compose 配置。未知输入正常返回 unknown。它不主动连接目标，不进行漏洞检测，也不保证 Banner 声明与目标真实软件完全一致。

## 技术选择

- Go 标准库 `net/http`：只需两个接口，标准库已有路由、JSON 和超时能力，没有必须引入 Gin 的需求。将来接口数量和中间件需求增加时可以换用 Gin，识别引擎无需随之更改。
- 无数据库：请求直接计算并返回，当前没有识别历史、用户管理或资产查询需求。规则保存在 JSON 中；如果需要持久化资产和查询历史，再引入数据库。
- 处理流程：扫描结果 JSON → client → HTTP server → 规则匹配 → 结果 JSON。

## 一键启动

需要已启动的 Docker Engine 和 Docker Compose 插件，首次构建需要拉取 Go 构建镜像。

```bash
docker compose up --build
```

server 健康后，client 自动读取 `data/sample.json`，在日志中输出 20 条结果并正常退出；server 持续运行。首次启动也可以直接运行 `docker compose up`，Compose 会构建缺失镜像。

更换输入文件后重新执行 client：

```bash
docker compose run --rm client -input /data/sample.json -server http://server:8080
docker compose down
```

把待处理文件放入 `data/` 并替换 `-input` 中的容器路径即可。服务默认没有宿主机端口映射；容器通过内部网络和服务名访问。Compose 文件是部署基础配置，不代表已经完成生产环境安全审计。

## 本地开发

需要 Go 1.26 或以上。在项目根目录运行：

```bash
go test ./...
go vet ./...
go run ./cmd/server
```

另一个终端运行：

```bash
go run ./cmd/client -input data/sample.json -server http://localhost:8080
curl http://localhost:8080/health
curl -X POST http://localhost:8080/fingerprint -H 'Content-Type: application/json' --data-binary @data/sample.json
```

## API 约定

`GET /health`：规则加载成功后才启动 HTTP 监听，健康接口返回 HTTP 200 和 `{"status":"ok"}`。

`POST /fingerprint`：请求体是 JSON 数组，响应为顺序相同的数组。

```json
[{"ip":"1.2.3.4","port":22,"banner":"SSH-2.0-OpenSSH_8.9p1 Ubuntu-3"}]
```

```json
[{"ip":"1.2.3.4","port":22,"protocol":"SSH","product":"OpenSSH","version":"8.9p1","os_hint":"Ubuntu","confidence":0.95}]
```

无法匹配时 `protocol` 为 `unknown`，`product`、`version`、`os_hint` 为空字符串，`confidence` 为 0。端口不会单独触发识别。HTTP 443 上的响应仍可识别为 HTTP。

请求最大 8 MiB，每批最多 1000 条，IP 必须有效，port 为 1–65535。空数组返回空数组。非法 JSON、null、非法 IP/port 和超限请求返回 HTTP 400 JSON 错误；未知 Banner 返回 HTTP 200。client 发生读取、请求或响应错误时返回非零退出码。

JSON 不支持题目中的 `\x00` 转义，请使用 `\u0000`；示例已经转换为合法 JSON。当前字符串输入不支持无损承载任意非 UTF-8 二进制；后续如需支持，应增加明确的 Base64 输入约定。

## 规则与边界

规则文件：`rules/fingerprints.json`，按数组顺序匹配，首条命中生效。字段含义：

| 字段 | 含义 |
| --- | --- |
| name | 规则名称 |
| pattern | Go RE2 正则表达式 |
| protocol / product | 输出协议与软件名称 |
| version_group | 提取版本的捕获组序号，0 表示不提取 |
| os_pattern | 可选系统提示正则，提取首个匹配文本 |
| confidence | 0–1 的证据强度评分，非统计准确率 |

当前覆盖 OpenSSH、HTTP nginx/Apache/Jetty/IIS、MySQL 握手、部分 Redis 响应、ProFTPD/vsFTPd/Pure-FTPd。TLS、其他协议、未覆盖的 Banner 和不完整握手可返回 unknown。规则启动时加载并编译；修改后需要重启 server，不支持热更新。配置错误直接阻止启动。

## 部署与项目布局

多阶段构建产出 CGO 关闭的独立二进制；scratch 运行镜像不携带编译器或 shell。两个运行镜像均使用 UID/GID 65532，根文件系统只读，移除 capabilities，禁止提权，限制内存、CPU 和进程数。规则和输入以只读卷挂载。server 使用自身二进制检查 `/health`，client 依赖 `service_healthy`。server 设置 HTTP 超时并处理 SIGTERM 优雅退出。

```text
cmd/server/          HTTP 服务与健康检查入口
cmd/client/          独立文件提交程序
internal/client/     文件校验、HTTP 调用和结果输出
internal/fingerprint/ 数据模型、输入校验和规则引擎
internal/httpapi/    HTTP 路由、错误响应和可观测中间件
internal/logging/    server/client 统一结构化日志
rules/              可独立维护的 JSON 指纹规则
data/               自测输入
Dockerfile          两个多阶段构建目标
compose.yaml        内部网络、健康依赖和权限配置
```

## 验证证据与后续工作

`LOG_LEVEL` 支持 `DEBUG`、`INFO`、`WARN`、`ERROR`，默认 `INFO`。日志以 JSON 写入 stderr，识别结果写入 stdout。每个 HTTP 请求都会获得 `X-Request-ID`，server 会记录请求状态、耗时和响应大小；识别接口额外记录已识别/unknown 数量。为保护扫描数据，日志不记录 Banner、IP 和响应正文。Compose 为容器日志配置了大小和文件数量上限。

`go test ./...` 验证示例协议、SSH/MySQL 细节、非标准端口、大小写响应头、空/截断/未知输入以及 API 错误处理；`go vet ./...` 检查静态问题。测试来源位于 `internal/fingerprint/engine_test.go` 和 `internal/httpapi/handler_test.go`，结果可以通过上述命令复现。

初始化验证：Go 测试、静态检查和编译通过；本地独立 server/client 联调返回 20 条结果，其中 2 条为 unknown，健康检查和优雅退出通过；`docker compose config --quiet` 通过。Dockerfile 和 Compose 已完成静态审查；按当前要求未执行镜像构建及 Compose 容器流程。

后续应扩充未见 Banner 的回归数据、补充二进制编码支持。初始化阶段没有执行 GitHub 上传；最终提交需要另行核验仓库可访问性和题目截止时间。
