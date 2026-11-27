# Clash Rules Simple

从 [Loyalsoldier/clash-rules](https://github.com/Loyalsoldier/clash-rules) 的 `release` 分支拉取规则，按直连、代理和拦截合并成三个 Mihomo / Clash Meta 规则集。[GitHub Actions](https://github.com/qianye9998/clash-rules-simple/actions/workflows/update-rules.yml) 每天北京时间 08:10 检查上游，有变更时更新 `main` 分支。

## 拉取地址

| 规则集 | 用途 | 下载地址 |
| --- | --- | --- |
| `direct` | 私有域名、Apple/iCloud、国内域名、局域网和国内 IP | [direct.yaml](https://raw.githubusercontent.com/qianye9998/clash-rules-simple/main/rules/direct.yaml) |
| `proxy` | Google、其他代理域名和 Telegram IP | [proxy.yaml](https://raw.githubusercontent.com/qianye9998/clash-rules-simple/main/rules/proxy.yaml) |
| `reject` | 广告与跟踪域名 | [reject.yaml](https://raw.githubusercontent.com/qianye9998/clash-rules-simple/main/rules/reject.yaml) |

三份规则均使用 `behavior: classical` 和 `format: yaml`。把 [clash-example.yaml](clash-example.yaml) 中的 `rule-providers` 和 `rules` 合并到 Mihomo 配置，并将 `PROXY` 改为已有的代理策略组名称。客户端示例每 86,400 秒检查一次更新。

匹配顺序为 **基础局域网直连 → 拦截 → 代理 → 直连 → 默认代理**。例如域名同时出现在直连与代理文件中时走代理，匹配广告规则时优先拦截。每个文件独立去重，跨文件重叠留给客户端按顺序处理。启用 DNS 解析时，国内与 Telegram 的 IP 规则也能匹配域名解析出的地址。局域网网段规则使用 `no-resolve`，请保留 `RULE-SET,direct,DIRECT` 的写法。

合并后客户端每轮只需拉取三个文件。规则仍由内核逐条匹配，加载成本取决于规则总量和类型。

## 更新和验证

使用 Python 3.12。

```sh
python3.12 -m venv .venv
source .venv/bin/activate
python -m pip install -r requirements.txt
python -m unittest discover -s tests -v
python scripts/update_rules.py
python scripts/update_rules.py --check
python scripts/verify_mihomo.py /path/to/mihomo
```

在 [`sources.yaml`](sources.yaml) 中增删或替换来源。域名的裸写法保留精确匹配，`+.example.com` 匹配根域和子域。当前启用的上游只有这两种写法。遇到 `*.example.com`、`.example.com` 或其他未支持模式时，脚本会报告来源与条目号，整次更新失败并保留上次输出。IP 规则区分 IPv4 和 IPv6，只有配置 `no-resolve: true` 的 IP 来源会添加该选项。`classical` 来源支持域名、IP 和进程名称或路径规则，默认未启用进程规则。

工作流在抓取失败或内核验证失败时停止提交。也可在 **Actions → Update Clash rules → Run workflow** 手动更新。北京时间 08:10 是计划触发时间，实际运行可能排队。公开仓库连续 60 天无活动时 GitHub 可能停用定时工作流，可在同一页面选择 **Enable workflow**。仓库的 Actions 策略需允许 `GITHUB_TOKEN` 写入。若默认分支要求通过 Pull Request 变更，则需相应调整发布方式。

## 来源和授权

本仓库把上游数据转换成 `classical` 格式，并按用途去重和排序。生成器及改编的规则集合保留 [GNU GPL v3 许可文本](LICENSE)。个别数据来源同时适用原许可，以下列出直接上游及其当前生成流程引用的数据项目。

| 项目 | 本项目用到的数据 | 上游许可 |
| --- | --- | --- |
| [Loyalsoldier/clash-rules](https://github.com/Loyalsoldier/clash-rules) | 三个规则文件的直接上游 | [GPL-3.0](LICENSE) |
| [Loyalsoldier/v2ray-rules-dat](https://github.com/Loyalsoldier/v2ray-rules-dat) | `direct`、`proxy`、`reject` 的主要域名数据 | [GPL-3.0](https://github.com/Loyalsoldier/v2ray-rules-dat/blob/master/LICENSE) |
| [Loyalsoldier/domain-list-custom](https://github.com/Loyalsoldier/domain-list-custom) | Private、iCloud | [MIT](licenses/domain-list-custom-MIT.txt) |
| [felixonmars/dnsmasq-china-list](https://github.com/felixonmars/dnsmasq-china-list) | Apple、Google | [WTFPL v2](licenses/dnsmasq-china-list.txt) |
| [Loyalsoldier/geoip](https://github.com/Loyalsoldier/geoip) | LAN、中国大陆和 Telegram 网段 | [CC BY-SA 4.0](licenses/geoip-CC-BY-SA-4.0.txt) 与 [GPL-3.0](licenses/geoip-GPL-3.0.txt) |
