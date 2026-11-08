# 安全加固设计与验证记录

日期：2026-11-07（America/Los_Angeles）。上游基线：1f4eebaaf3baa5e1d9fb41f38cf74348f03f0ec9。目标仓库：baobalas/cloudflare-tunnel-skill。保留现有许可证与 Quick/Named 两种用途。

## 需求与范围

修复审核中发现的输入注入、缺少明确访问方式、后台生命周期、状态文件信任、安装版本和验证结果问题。仅修改本 skill 的代码、文档和测试。默认离线测试；可选真实测试只公开一次性虚构页面。没有使用用户账号凭据、修改 DNS/Access、发布业务服务或安装全局 skill。

## 设计决定

| 原问题 | 加固行为 |
| --- | --- |
| 缺少明确访问方式 | Quick 必须选择具体邮箱或 --public；能力不足拒绝启动。Named 必须声明已有 Access 或明确 public/app-auth 决策；声明不等于验证。 |
| curl 参数注入、隐式代理绕过/DoH | 改用标准库 HTTP 客户端；严格 HTTP(S) URL；公网保留代理/系统 DNS，只有 loopback 检查直连；不自动重定向。 |
| URL 可指向内网或携带秘密 | 原点只接受 loopback，不接受 userinfo/query/fragment/path；localhost 规范化到 127.0.0.1。 |
| YAML 字符串注入 | 域名严格校验，配置通过 JSON 序列化（YAML 子集），仅一个 origin 和最终 404。 |
| 无最长寿命、异常遗留后台进程 | 独立监督进程持有独占租约，缺省 900 秒，最多 86400；启动失败、到期、普通终止、停止请求及日志超限清理真实 child handle。 |
| PID 复用或篡改导致误杀 | 不再信任持久化 PID；停止发送匹配运行标识的私有请求，监督进程只操作自身创建的实际子进程。 |
| 不安全链接/文件权限 | 项目外 0700 状态、0600 文件；逐层 dirfd + O_NOFOLLOW，拒绝硬链接/特殊文件/不安全所有者和共享可写祖先；原子写入。 |
| 同名配置覆盖和名称冲突 | Named 使用 named- 名称空间；以原子不覆盖创建阻止并发覆盖；Quick 与 Named 配置互不覆盖。 |
| 误报 HTTP 成功 | 默认仅 2xx 成功，可检查预期内容或明确预期状态；401/403/404/登录跳转不再默认通过。 |
| 安装漂移或固定临时路径 | 用户选定完整提交；独立临时 clone，失败即停；安装器只读固定 Git blobs，拒绝旧目录/链接/非普通文件并保存 SHA-256 清单。 |
| 账号级运行凭据 | Named 使用明确提供的私有 tunnel JSON 和 TunnelID；只引用路径，不复制密钥，不要求运行时 cert.pem。 |

运行器删除子进程环境中继承的 TUNNEL_/CLOUDFLARED_/CF_TUNNEL_ 配置，避免已有账号/路由设置改变 Quick 行为。它不修改系统环境或网络配置。后台状态由锁保护，已有运行实例不会被静默替换。

受管后台实现有意限定为 macOS/Linux/WSL，原生 Windows 不再使用未核验的 taskkill。Named 的直接前台运行按 Ctrl-C 停止，不使用 Quick 的自动到期。

## 本地验证

平台：macOS 27.2、Apple Silicon。Python 3.15.2 和隔离的 Python 3.10.22 各执行 27 项测试，全部通过。

~~~bash
python3 scripts/test_quick_tunnel.py
uv run --python 3.10 python -m unittest discover -s tests -v
python3 -m py_compile scripts/tunnel_helper.py scripts/install_skill.py scripts/test_quick_tunnel.py
~~~

覆盖实际本机 HTTP、真实离线替身进程启动/停止/到期、跨目录管理、并发拒绝、启动超时/退出、启动后状态写入故障、伪造 PID 无信号、权限/符号链接/硬链接/FIFO、URL/域名/换行输入、HTTP 状态/重定向、代理策略、自签名 HTTPS、固定提交安装及同名配置受控并发。

结构验证：系统 skill validator 通过。Git 空白检查与脚本语法检查通过。GitHub workflow 已配置 macOS/Linux × Python 3.10/3.13 离线回归；Actions 固定到已核验的完整提交，最小只读权限，不持久化 checkout 凭据。云端实际结果以该提交对应 Actions 为准。

独立验证者在自己的临时目录使用虚构资料，实测 Quick 启停/到期/跨目录命令、Named 配置和权限。发现的配置名称冲突与并发覆盖均已修复，以相同场景复验通过，并加入回归测试。

## 官方二进制兼容性与真实连通性

使用官方 cloudflare/cloudflared 2026.10.7 的 darwin-arm64 发布文件，仅放在忽略的本地 .tools/，未安装到系统。

发布归档的 SHA-256 与 GitHub Release asset digest 一致：

~~~text
3586ccf397e98e5f437e60e7c307ca6ac463e110580503af8bb8e6f9ebf831bd
~~~

实际检查结果：

- --version 和邮箱能力探测通过，支持 --allowed-mail。
- 使用虚构 tunnel JSON 生成的配置，通过该二进制 ingress validate。
- 显式 --live 测试成功启动 40 秒上限的 Quick Tunnel，只公开临时专用目录里的虚构单页；外部 URL 返回预期随机标记。
- 测试结束后 stop 和 status 共同确认 running:false。没有公开项目目录或真实凭据。

~~~bash
python3 scripts/test_quick_tunnel.py --live --cloudflared .tools/2026.10.7/cloudflared
~~~

## 验证边界与后续使用

这不是绝对安全保证。实际邮箱 OTP、Cloudflare Access、固定域名 DNS、webhook 签名及用户业务认证没有在本次测试中执行；上线前需要对具体应用验证匿名拒绝与授权成功。

--public 是明确开放选择，不会替应用增加登录。--access-protected 只是操作者声明。helper 无法自动发现应用的全部敏感路由。

同用户恶意进程与特权攻击不在文件权限隔离范围内。SIGKILL 监督进程可阻止其清理，应人工核查实际剩余进程。旧版 PID/项目状态不自动迁移或删除，升级前单独检查旧隧道。

官方参考：
- https://developers.cloudflare.com/tunnel/get-started/quick-tunnels/
- https://developers.cloudflare.com/tunnel/features/locally-managed-tunnels/configuration-file/
- https://developers.cloudflare.com/cloudflare-one/access-controls/applications/http-apps/self-hosted-public-app/
- https://developers.cloudflare.com/cloudflare-one/networks/connectors/cloudflare-tunnel/do-more-with-tunnels/local-management/tunnel-permissions/
