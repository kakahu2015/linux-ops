---
name: linux-ops
description: 通过现有 Linux Ops SSH primitives 和 agent gate 观察、诊断或执行有界的远程 Linux 运维。适用于主机、服务、网络、软件包、文件和进程操作；不用于应用代码修复。
---

# Linux Ops for Codex CLI

这是现有 Linux Ops v3 的 Codex CLI 适配层。它复用本机的脚本、inventory、autonomy policy 和审计目录，不复制或替代运行时。

## 运行时与适用规则

- 当前 Linux Ops 运行时目录：`/root/.openclaw/workspace/skills/linux-ops`。它只提供脚本、inventory、policy 和审计目录；命令中记为 `OPS_ROOT`，并使用绝对路径调用脚本。
- 每次远程操作前，读运行时 `SKILL.md` 中的操作规则与接口，以及实际的 `autonomy.yaml`、`scripts/policy.yaml` 和 `scripts/primitive_rules.json`。遵循当前 Codex 指令和当前任务适用的 `AGENTS.md`；不要把 OpenClaw workspace 的 `AGENTS.md` 或运行时 `SKILL.md` 的 `Constitutional Authority` 部分当作 Codex 宪章。
- 遇到当前 Codex 指令、适用的工作区规则、Linux Ops 操作规则或 gate 之间的实际冲突，或授权范围不清楚时，停止并说明。
- 使用实际的 `autonomy.yaml`，不要用 `autonomy.example.yaml` 代替，也不要为了让 gate 放行而修改 policy、primitive rules 或决策记录中的风险判断。
- 如果运行时目录不存在，先定位唯一的 Linux Ops v3 checkout；找不到或存在多个候选时停止，不要绕过 gate 改用裸 SSH。

## 安全边界

- `.secrets/`、私钥、密码、token 和认证文件只允许由运行时按需读取；不要打开、打印、复制或写入决策记录。不要把真实 IP、邮箱或其他私有基础设施标识写入决策记录或最终答复。运行时输出和审计信息也要先检查脱敏结果。
- 所有远程操作都必须经过 `scripts/agent_gate.sh` 和有效的 decision record。不要直接运行 primitive、`ssh`、`scp`、`sshpass`，或用其他脚本绕过 gate。
- 原始远程命令不是默认路径。只有用户明确指定了具体命令、gate 接受该操作且 policy 允许时，才可通过 gate 使用 raw exec，并按 gate 要求传入 `--allow-raw-exec`；不得用 `--test-mode` 执行真实操作。
- L4 操作必须有明确授权；具体、明确的用户指令可作为该操作的授权。若请求笼统、目标不明、影响范围不明，或 gate/policy 要求的授权没有覆盖具体操作，先停下询问。L5 永不执行。
- 生产环境、认证与持久化状态、防火墙、锁定访问风险、破坏性变更，以及超出 policy 的主机数量都按 gate 和 policy 的最高限制处理。批量变更先做 canary；gate 拒绝时不得换 primitive、拆分主机或改参数来规避拒绝。

## 操作流程

1. 明确目标主机别名、环境、期望结果与请求授权范围。先用有界的只读观察确认当前状态；不要把“检查”扩展成修复。
2. 为当前单个操作准备 decision record，按 `schemas/decision-record.schema.json` 填写意图、观察、风险、primitive、验证、停止条件，以及适用的回滚动作。记录中不得包含凭据或私有基础设施标识；将 `DECISION` 设为该记录的完整路径。复杂工作可按实际阶段拆分，但不得为绕过主机数限制或 gate 拒绝而拆分；多主机变更先做 canary，并遵守 policy 的并发数和超时限制。
3. 验证决策和活动 policy，并对同一决策执行 dry-run：

   ```bash
   OPS_ROOT=/root/.openclaw/workspace/skills/linux-ops
   python3 "$OPS_ROOT/scripts/validate_decision.py" "$DECISION" --quiet
   python3 "$OPS_ROOT/scripts/validate_autonomy.py" "$OPS_ROOT/autonomy.yaml" --quiet
   bash "$OPS_ROOT/scripts/agent_gate.sh" --decision "$DECISION" --policy "$OPS_ROOT/autonomy.yaml" --dry-run
   ```

4. 只有在 dry-run 成功、用户请求覆盖该操作且 policy 所需授权已满足时，才用同一份决策执行：

   ```bash
   bash "$OPS_ROOT/scripts/agent_gate.sh" --decision "$DECISION" --policy "$OPS_ROOT/autonomy.yaml" --execute
   ```

   dry-run 与执行必须使用相同的目标、primitive、参数、风险级别和已授权的 gate flags。只有用户明确授权了对应风险动作且 gate 要求时，才传入相关 `--confirm-*` 选项；这些 flags 不能代替用户授权。

5. 从真实主机状态验证结果。优先使用 decision record 中的 `verification_actions`；需要额外检查时，另建只读决策并再次过 gate。若验证失败且已定义安全回滚，则按 gate 执行回滚并验证；若结果含糊、回滚不可用或 gate 报错，停止后续操作并升级说明。
6. 向用户分别说明观察到的状态、实际执行的操作、验证结果和未解决的不确定性。不要把 dry-run 成功描述成已执行，也不要把脚本退出码单独当作业务结果。

## 按需参考

- 操作边界、自治级别和接口：`/root/.openclaw/workspace/skills/linux-ops/SKILL.md`
- 决策记录字段：`/root/.openclaw/workspace/skills/linux-ops/schemas/decision-record.schema.json`
- 现有 primitive 与限制：`/root/.openclaw/workspace/skills/linux-ops/scripts/primitive_rules.json`
