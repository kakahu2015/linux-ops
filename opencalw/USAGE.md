# 自动化工作流使用说明

## 概述

这个自动化工作流用于同步 `kakahu2015/synapse` 仓库与上游仓库，并自动更新 `kakahu/cloudflare-turn-18472` 仓库。

## 工作流原理

1. **同步上游**：将 `element-hq/synapse` 的更改同步到本地 `develop` 分支
2. **推送触发**：推送到 `kakahu2015/synapse` 的 `develop` 分支触发 GitHub Actions
3. **自动检查**：Actions 检查 `cloudflare-turn-18472` 是否落后于 `synapse` 的 `develop` 分支
4. **自动同步**：如果落后，自动在 `cloudflare-turn-18472` 仓库中执行 rebase
5. **冲突处理**：如果冲突，创建 Issue 通知手动解决

## 部署工作流

### 第一步：克隆你的 fork（如果还没有）

```bash
git clone https://github.com/kakahu2015/synapse.git
cd synapse
git remote add upstream https://github.com/element-hq/synapse.git
```

### 第二步：运行部署脚本

将以下文件复制到你的 synapse fork 目录：
- `.github/workflows/rebase-cf-turn.yml`
- `deploy-workflow.sh`
- `sync-upstream.sh`
- `conflict-resolution-guide.md`
- `USAGE.md`

然后运行部署脚本：

```bash
./deploy-workflow.sh
```

这将：
1. 复制工作流文件到 `.github/workflows/`
2. 创建 `patch-conflict` 标签
3. 提交并推送到 `develop` 分支

## 日常使用

### 同步上游（日常操作）

运行同步脚本：

```bash
./sync-upstream.sh
```

或者手动执行：

```bash
git fetch upstream
git checkout develop
git merge upstream/develop --ff-only
git push origin develop
```

**这一步会自动触发 GitHub Actions**，将 `kakahu/cloudflare-turn-18472` rebase 到最新。

### 手动触发（Dry Run 测试）

```bash
gh workflow run rebase-cf-turn.yml --repo kakahu2015/synapse -f dry_run=true
```

## 冲突处理

当工作流检测到冲突时：

1. 你会收到一个 Issue 通知（在 `kakahu/cloudflare-turn-18472` 仓库中）
2. 按照 `conflict-resolution-guide.md` 中的步骤手动解决冲突
3. 解决后关闭 Issue

## 文件说明

### 工作流文件
- `.github/workflows/rebase-cf-turn.yml`：GitHub Actions 工作流

### 脚本文件
- `deploy-workflow.sh`：部署工作流的脚本
- `sync-upstream.sh`：日常同步上游的脚本

### 文档文件
- `USAGE.md`：本使用说明
- `conflict-resolution-guide.md`：冲突解决指南
- `README-workflow.md`：工作流详细说明

## 常见问题

### Q: 工作流没有触发
A: 检查工作流文件是否在正确的位置，并确保推送的是 `develop` 分支。

### Q: 没有权限推送
A: 确保 `GITHUB_TOKEN` 有权限推送到 `kakahu/cloudflare-turn-18472` 仓库。可能需要使用个人访问令牌（PAT）。

### Q: 冲突总是发生
A: 考虑更频繁地同步上游，或与其他开发者协调避免同时修改同一部分代码。

### Q: 如何查看工作流运行状态
A: 使用以下命令：
```bash
gh run list --repo kakahu2015/synapse --workflow rebase-cf-turn
```

## 高级配置

### 自定义工作流触发条件

编辑 `.github/workflows/rebase-cf-turn.yml`，修改 `on` 部分：

```yaml
on:
  push:
    branches: [ develop ]
    paths:
      - 'src/**'  # 只在 src 目录更改时触发
```

### 修改分支比较逻辑

当前逻辑检查 `synapse` 的提交是否在 `cloudflare-turn-18472` 的历史中。你可以根据需要调整比较方法。

### 添加更多通知

在工作流中添加更多通知步骤，例如 Slack 或邮件通知。

## 监控和维护

1. **定期检查工作流运行状态**
2. **查看冲突频率**，如果太高需要调整工作流程
3. **更新工作流**以适应项目结构变化

## 联系支持

如果遇到问题：
1. 查看 GitHub Actions 运行日志
2. 检查冲突解决指南
3. 在相关仓库中创建 Issue 寻求帮助