# ZeroTrace 协作开发流程规范

为了提高团队协作效率、保证代码质量，并充分利用 GitHub 的开源协作特性，我们制定了以下开发流程规范。

## 1. 工具与环境准备

推荐使用现代 IDE（如 VS Code, Cursor, Windsurf 或 IntelliJ IDEA）进行开发，并安装 Git 相关插件（例如 GitLens）。
这样可以：
- 自动显示每行代码的最后一次修改记录和修改人。
- 在编辑器内直接查看和对比 commit 记录。
- 更好地处理分支切换和冲突解决。

## 2. 分支管理模型

我们采用经典的分支管理策略，主要包含以下分支类型：

### 2.1 主分支 (`main`)
- **定位**：稳定版本的代码。
- **规则**：
  - 任何时候，`main` 分支的代码都应该是可直接编译和运行的。
  - 用户拉取该分支代码后无需额外配置即可使用。
  - **禁止**直接向 `main` 分支进行 `git push` 提交。所有合并必须通过 Pull Request (PR) 并在测试通过后完成。

### 2.2 开发分支 (`dev`)
- **定位**：日常开发的集成主干。
- **规则**：
  - 所有的功能开发、Bug 修复合并都首先进入 `dev` 分支。
  - `dev` 分支应当保持相对稳定，但允许存在尚未发布的新特性。
  - 定期将测试稳定后的 `dev` 分支合并到 `main` 分支。

### 2.3 个人特性/修复分支 (`dev/<username>/<feature-name>`)
- **定位**：每个开发人员的独立工作区。
- **规则**：
  - 命名规范推荐为：`dev/姓名首字母/功能简述`（例如：`dev/zhangsan/fix-agent-bpf`）或 `feature/<feature-name>`。
  - **修复 Bug 分支**：`bugfix/<username>/<bug-name>` 或 `hotfix/<username>/<bug-name>`。
  - **文档更新分支**：`docs/<username>/<doc-name>`。
  - 从最新的 `dev` 分支检出。
  - 开发完成后，向 `dev` 分支发起 Pull Request (PR)。

## 3. Commit 提交规范 (Conventional Commits)

为了让 Git 历史清晰易读，在执行 `git commit` 时，必须遵循格式：
`<type>: <subject>`

**常见 Type 类型：**
- `feat`: 新增功能 (Feature)
- `fix`: 修复 Bug
- `docs`: 文档变更
- `style`: 代码格式修改（不影响逻辑）
- `refactor`: 重构（既不是新增功能也不是修复 bug 的代码变动）
- `test`: 新增或修改测试
- `chore`: 构建过程或辅助工具的变动

**示例：**
- `feat: 新增 eBPF HTTP2 流量抓取支持`
- `fix: 修复 managed 模式下 dispatcher 意外停止的问题`
- `docs: 更新测试文档增加 cpu 子命令说明`

## 4. 标准开发工作流

### Step 1: 同步并创建分支
在开始新功能或修复前，请确保本地代码是最新的：

```bash
# 切换到 dev 分支
git checkout dev

# 拉取最新的远程 dev 代码
git pull origin dev

# 创建并切换到个人的开发分支
git checkout -b dev/yourname/feature-name
```

### Step 2: 开发与提交 (Commit)
在你的分支上进行代码修改，并遵循良好的 commit 习惯：
- **提交频率**：完成一个逻辑小点后即可提交，不要把几天的工作攒成一个巨大的 commit，保持小步快跑。
- **自测要求**：提交前确保代码在本地能够编译通过，且基本功能测试正常。

```bash
git add .
git commit -m "feat: 你的提交说明"
```

### Step 3: 推送并提交 Pull Request (PR)
当你完成了当前功能的开发，准备合并代码时：

```bash
# 将本地分支推送到 GitHub
git push origin dev/yourname/feature-name
```
然后去 GitHub 仓库页面，针对 `dev` 分支发起一个 Pull Request (PR)。

**PR 填写规范：**
- **Title**: 简明扼要说明 PR 的目的，可与主要 commit 保持一致。
- **Description**: 
  - 这个 PR 解决了什么问题？（附上 Issue 链接如果有）
  - 主要的代码改动点在哪里？
  - 如何进行测试来验证你的代码？

### Step 4: 代码审查 (Code Review)
- PR 提交后，请至少邀请 **一位团队成员** 进行 Review。
- 可以在 GitHub 的 Files changed 面板中逐行审查代码。
- **对于 Reviewer**：不仅要看逻辑是否正确，还要关注代码风格、潜在的性能问题和可维护性。
- 如果 Reviewer 提出修改建议，请在本地修改后执行 `git commit` 或 `git commit --amend`，并重新 push，PR 会自动更新。

### Step 5: 合并到 `dev`
- 当 Review 获得 "Approve" 批准，并且所有的测试（如果有 CI 流程）通过后，由 Reviewer 或维护者将 PR 合并入 `dev` 分支。
- **合并策略**：推荐使用 "Squash and merge"，将你的多个开发小 commit 压缩成一个干净的 commit 进入 dev。
- 合并后，可安全删除你的个人开发分支。

### Step 6: 稳定发布到 `main`
- 经过在 `dev` 分支上的一段测试时间后，由核心维护者发起从 `dev` 到 `main` 的 PR。
- 确保所有的功能都能稳定运行，最终合并到 `main` 作为最新稳定版发布，并可打上对应版本的 Tag。

## 5. 冲突解决
在开发过程中，如果 `dev` 分支被其他人更新，导致与你的个人分支产生冲突，请通过 `rebase` 来解决：

```bash
# 切换到 dev 拉取最新代码
git checkout dev
git pull origin dev

# 切换回自己的分支
git checkout dev/yourname/feature-name

# 将自己的修改"变基"到最新的 dev 之上
git rebase dev

# 此时如果有冲突，IDE 会高亮显示。在编辑器中解决冲突后：
git add .
git rebase --continue
# 重复上述过程直到 rebase 成功
```
解决冲突并测试无误后，你可能需要强制推送（如果之前已经 push 过这个分支）：
```bash
git push -f origin dev/yourname/feature-name
```

## 6. 总结核心原则
- **代码获取**：永远基于最新的 `dev` 开发。
- **代码编写**：永远在个人分支 (`dev/xxx` 或 `feat/xxx`) 开发。
- **代码提交**：遵循小颗粒度和 `Conventional Commits` 规范。
- **代码合并**：永远通过 PR 发起，且**必须经过 Code Review**。
- **稳定版本**：只有完全通过测试的代码才能进入 `main` 分支。
