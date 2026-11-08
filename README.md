# Cloudflare Tunnel Skill — 安全加固版

baobalas 的加固 fork，基于上游提交 1f4eebaaf3baa5e1d9fb41f38cf74348f03f0ec9，保留 MIT 许可证。

[English](README_EN.md) · [加固设计与测试记录](docs/HARDENING.md)

需要 Python 3.10+、可信来源的 cloudflared 和 macOS/Linux/WSL。原生 Windows 请使用 WSL。发布一个端口可能同时公开后台、API、调试页面和文件；敏感服务须先落实应用认证或 Cloudflare Access。

## 安装已审核的提交

优先项目级安装。在本仓库提交历史中审阅并复制完整 40 位 SHA，替换下方 REVIEWED_COMMIT_SHA。任一步失败立即停止；临时目录唯一；已有安装目录拒绝覆盖。

~~~bash
(
  set -eu
  SKILL_REVISION='REVIEWED_COMMIT_SHA'
  SKILL_TEMP="$(mktemp -d)"
  trap 'rm -rf -- "$SKILL_TEMP"' EXIT
  git clone --no-checkout -- https://github.com/baobalas/cloudflare-tunnel-skill.git "$SKILL_TEMP/repo"
  git -C "$SKILL_TEMP/repo" checkout --detach "$SKILL_REVISION"
  python3 "$SKILL_TEMP/repo/scripts/install_skill.py" \
    --expected-commit "$SKILL_REVISION" \
    --destination "$PWD/.codex/skills/cloudflare-tunnel"
)
~~~

Claude Code 项目级目录改为 .claude/skills/cloudflare-tunnel。需要全局安装时明确指定 ~/.codex/skills/cloudflare-tunnel 或 ~/.claude/skills/cloudflare-tunnel。安装器只读取固定提交内的普通文件，包括 agents、scripts、references，保存 SHA-256 清单；不采用未提交内容，不启动服务、不登录账号。升级请选择新目录并保留旧版。

## 临时预览

在安装目录运行，或使用 helper 的绝对路径：

~~~bash
python3 scripts/tunnel_helper.py check
python3 scripts/tunnel_helper.py quick \
  --url http://127.0.0.1:3000 \
  --allowed-mail viewer@example.com --duration 900
~~~

替换为实际允许的访客邮箱，可重复 --allowed-mail。不支持邮箱验证的 cloudflared 会被拒绝，不会自动变成公开访问。邮箱 OTP 需要访客浏览器交互，不适合 webhook。

明确授权的无敏感数据公开演示：

~~~bash
python3 scripts/tunnel_helper.py quick --port 3000 --public --duration 900
~~~

--public 允许公众连接，不提供登录保护。缺少访问方式选择会拒绝启动。--duration 从启动起计时，默认 900 秒，最大 86400；--timeout 只控制启动等待。监督进程在到期、停止请求、启动失败、普通终止信号或日志超过 1 MiB 时清理子进程。并发启动拒绝替换旧隧道。

~~~bash
python3 scripts/tunnel_helper.py status
python3 scripts/tunnel_helper.py stop
python3 scripts/tunnel_helper.py verify \
  --url https://example-preview.trycloudflare.com --contains 'expected application content'
~~~

使用启动输出中的完整 status_command/stop_command，可从其他目录调用。缺省 status/stop 按当前项目定位。verify 默认只接受 2xx，不跟随重定向，可显式 --expect-status 401；受限服务还须验证匿名拒绝和授权成功。

源地址只接受 localhost 或字面 loopback IP，不接受用户名、密码、查询参数或路径。localhost 转为 127.0.0.1；仅监听 IPv6 时用 [::1]。自签名本机 HTTPS 优先使用 --ca-file，也可显式 --no-tls-verify；选择同时应用于本地检查和源站连接。公网验证保持 TLS 检查，尊重代理和系统 DNS，不自动切换 DoH。

## 固定域名

先配置并测试认证，再发布 DNS。helper 只生成配置：

~~~bash
python3 scripts/tunnel_helper.py named-config \
  --name my-app --hostname app.example.com --port 3000 \
  --credentials-file /absolute/path/tunnel-uuid.json --access-protected
~~~

凭据须为当前用户所有、0600 或更严格、无符号/硬链接的隧道专用 JSON。配置引用其绝对路径并使用 TunnelID，不复制密钥，不要求运行时携带账号级 cert.pem。--access-protected 是操作者声明，不代表 helper 已验证 Access。公开演示或应用自行认证可显式 --public。

配置以 JSON（合法 YAML 子集）序列化，只有一个服务规则和最终 404，私有保存且拒绝覆盖。按输出的 run_command 前台运行，用 Ctrl-C 停止；Named 前台运行没有 Quick 的自动到期。详细流程见 references/named-tunnel.md。

## 状态与升级

默认在 XDG_STATE_HOME（未设置时 ~/.local/state）下的 cloudflare-tunnel-skill/项目路径摘要/，目录 0700、文件 0600，可指定 --state-dir。拒绝符号链接路径、硬链接、特殊文件、不安全所有者或共享可写祖先。停止通过监督进程的运行标识完成，不信任磁盘 PID。

旧版 .cloudflare-tunnel/ 不自动读取、迁移或删除；新 helper 不能管理旧版进程。升级前检查并停止旧隧道。监督进程遭到 SIGKILL 时无法保证执行清理，应人工核实对应实际进程，不得猜测 PID。

## 测试

~~~bash
python3 -m unittest discover -s tests -v
python3 -m py_compile scripts/tunnel_helper.py scripts/install_skill.py scripts/test_quick_tunnel.py
python3 scripts/test_quick_tunnel.py
~~~

默认完全离线，访问本机站点并使用真实的模拟子进程，不创建公网隧道。真实测试须显式：

~~~bash
python3 scripts/test_quick_tunnel.py --live --cloudflared /trusted/path/cloudflared
~~~

真实测试只公开一次性虚构测试页，带时限和退出清理。离线测试不代表公网、邮箱 OTP、Access 或业务认证通过。Quick Tunnel 仅适合测试，有可用性、并发和 SSE 限制。
