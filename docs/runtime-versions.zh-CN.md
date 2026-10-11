# 本机集成与版本记录

以下版本是在本机于 **2026-10-11（Asia/Singapore）** 通过命令行读取的快照。它记录当时安装的版本，不代表兼容范围或依赖锁定；升级后请重新读取并更新。

## 应用版本

| 组件 | 本机版本 | 本仓库对应内容 | 命令与可执行文件 |
| --- | --- | --- | --- |
| Codex CLI | `codex-cli 0.162.1` | [`codex/SKILL.md`](../codex/SKILL.md)：本机 Codex Linux Ops 适配层 | `codex --version`；`/root/.local/bin/codex` |
| OpenClaw | `2026.9.9 (bcfc888)` | `opencalw/`：OpenClaw agent/skill 配置 | `openclaw --version`；`/usr/bin/openclaw` |

## 共享运行组件

| 组件 | 本机版本 | 说明 |
| --- | --- | --- |
| Linux Ops Skill | `3.0.0` | `SKILL.md` 中的 skill 版本；与 Codex CLI、OpenClaw 的应用版本分别维护。 |
| Node.js | `v24.16.0` | 本机运行时版本，不是 Codex 或 OpenClaw 的应用版本。 |

Codex 适配层复用既有 Linux Ops 运行时；OpenClaw 应用版本和 Codex CLI 版本属于两套独立产品版本。不要用其中一个版本号替代另一个，也不要把 Linux Ops Skill 的 `3.0.0` 当作任一应用版本。

复核命令：

```bash
codex --version
openclaw --version
node --version
```
