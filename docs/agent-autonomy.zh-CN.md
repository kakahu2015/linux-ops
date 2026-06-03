# Agent 自治模型

[中文](agent-autonomy.zh-CN.md) | [English](agent-autonomy.md)

这份文档只保留设计底线；**运行规则以 `../SKILL.md` 为准**。

## 核心

- skill 提供 Linux primitives
- Agent 提供推理、诊断、序列选择和判断
- 不要把 skill 写成固定修复脚本
- 不要在无人值守里做无边界扫描或破坏性操作

## 推荐循环

```text
observe -> classify -> decide -> gate -> execute -> verify -> stop / rollback / escalate
```

## 自治分层

- **L0**：只解释，不执行
- **L1**：只读观察
- **L2**：低风险、窄范围、可逆、可立即验证的动作
- **L3**：窄范围的紧急止血或明显安全修复
- **L4**：高风险、锁定风险、或会显著影响生产的动作，默认要确认
- **L5**：无人值守禁止

## 应该保留的东西

- 小而可组合的 primitives
- 结构化 JSON 输出
- gate / policy / audit / rollback
- 有界批量执行
- inventory 校验
- 决策记录

## 不该放进来

- 业务专用 repair/deploy 脚本
- 隐藏 playbook
- 大而全的一键修复
- 无限制日志倾倒

## 一句话

**skill 管边界，Agent 管脑子。**
