https://reference.langchain.com/python/deepagents/graph/create_deep_agent

```python
create_deep_agent(
  model: str | BaseChatModel | None = None,
  tools: Sequence[BaseTool | Callable | dict[str, Any]] | None = None,
  *,
  system_prompt: str | SystemMessage | None = None,
  middleware: Sequence[AgentMiddleware] = (),
  subagents: Sequence[SubAgent | CompiledSubAgent | AsyncSubAgent] | None = None,
  skills: list[str] | None = None,
  memory: list[str] | None = None,
  permissions: list[FilesystemPermission] | None = None,
  backend: BackendProtocol | BackendFactory | None = None,
  interrupt_on: dict[str, bool | InterruptOnConfig] | None = None,
  response_format: ResponseFormat[ResponseT] | type[ResponseT] | dict[str, Any] | None = None,
  state_schema: type[DeepAgentState] | None = None,
  context_schema: type[ContextT] | None = None,
  checkpointer: Checkpointer | None = None,
  store: BaseStore | None = None,
  debug: bool = False,
  name: str | None = None,
  cache: BaseCache | None = None
) -> CompiledStateGraph[AgentState[ResponseT], ContextT, InputAgentState, OutputAgentState[ResponseT]]
```

# backends

### StateBackend(默认)

默认的「内存/状态虚拟磁盘」，轻量、隔离、适合草稿

```python
from deepagents import create_deep_agent
from deepagents.backends import StateBackend

# By default we provide a StateBackend
agent = create_deep_agent(model="openai:gpt-5.5")

# Under the hood, it looks like
agent2 = create_deep_agent(
    model="openai:gpt-5.5",
    backend=StateBackend(),
)
```

```
Agent 调用 write_file("/notes.md", "...")
        ↓
StateBackend 写入 graph state["files"]["/notes.md"]
        ↓
若配置了 checkpointer → 随 checkpoint 一起按 thread 保存
        ↓
同一 thread_id 下一轮 invoke → 文件还在
换 thread_id / 无 checkpointer → 文件相当于丢失
```

### FilesystemBackend 

操作的是 本机文件系统（在 root_dir 之下）。

```python
from deepagents import create_deep_agent
from deepagents.backends import FilesystemBackend

agent = create_deep_agent(
    model="openai:gpt-5.5",
    backend=FilesystemBackend(root_dir=".", virtual_mode=True),
)
```

- 可选 virtual_mode：把路径限制在 root_dir 内，降低目录穿越风险（不等于完整沙箱隔离）
- 默认 不提供 安全的远程沙箱；需要 shell 时通常配合 LocalShellBackend 或其它 Sandbox 后端

```
Agent 调用 write_file("/src/app.py", "...")
        ↓
FilesystemBackend 解析路径 → root_dir + 相对路径
        ↓
真正写入磁盘上的文件
```

### LocalShellBackend

LocalShellBackend = FilesystemBackend（真实磁盘文件） + 本机无隔离的 shell 执行（execute）。

它是 Deep Agents 里「能力最强、隔离最弱」的后端之一：agent 既能改你的项目文件，也能在本机直接跑命令。

```python
from deepagents import create_deep_agent
from deepagents.backends import LocalShellBackend

agent = create_deep_agent(
    model="openai:gpt-5.5",
    backend=LocalShellBackend(root_dir=".", virtual_mode=True, env={"PATH": "/usr/bin:/bin"}),
)
```

- Shell命令使用root_dir作为工作目录，但可以访问系统上的任何路径。

### StoreBackend

StoreBackend 是 Deep Agents 里把「虚拟文件」存进 LangGraph Store 的后端：文件可以跨 thread、跨会话长期保留，适合当长期记忆 / 共享知识库，而不是一次性草稿。

```python
from deepagents import create_deep_agent
from deepagents.backends import StoreBackend
from langgraph.store.memory import InMemoryStore

agent = create_deep_agent(
    model="openai:gpt-5.5",
    backend=StoreBackend(
        namespace=lambda rt: (rt.server_info.user.identity,),
    ),
    store=InMemoryStore(),  # Good for local dev; omit for LangSmith Deployment
)
```

```
Agent write_file("/memories/prefs.md", "...")
        ↓
StoreBackend 写入 LangGraph BaseStore
（按 namespace 组织路径）
        ↓
换 thread_id / 新会话仍可 read_file 读到
（只要同一个 store、同一 namespace）
```

### ContextHubBackend

ContextHubBackend 是 Deep Agents 里把「虚拟文件」存进 LangSmith Context Hub 仓库 的后端：用 Hub 做版本化、可协作的持久文件存储，主要承载驱动 agent 行为的上下文（AGENTS.md、skills、策略等），而不是当次运行的草稿。


### CompositeBackend 

CompositeBackend 是 Deep Agents 里的路由型文件系统后端：按路径前缀把不同目录交给不同 backend，实现「草稿临时、记忆持久、代码落盘」等混合存储。

```python
from deepagents import create_deep_agent
from deepagents.backends import (
    CompositeBackend,
    StateBackend,
    StoreBackend,
    FilesystemBackend,
)
from langgraph.store.memory import InMemoryStore

store = InMemoryStore()

agent = create_deep_agent(
    model="openai:gpt-4o",
    backend=CompositeBackend(
        default=StateBackend(),  # 草稿、工具大输出 → 临时
        routes={
            "/memories/": StoreBackend(),                           # 长期记忆
            "/workspace/": FilesystemBackend(
                root_dir="/path/to/project",
                virtual_mode=True,
            ),
        },
    ),
    store=store,  # StoreBackend 需要
)
```

```
Agent: read_file / write_file / ls / ...
        ↓
CompositeBackend 看路径前缀
        ├── /memories/*   → StoreBackend 或 ContextHubBackend（跨会话）
        ├── /workspace/*  → FilesystemBackend（真实项目）
        └── 其它          → StateBackend（线程内临时）
```

# Permissions

用一组规则告诉 agent：哪些路径能读、哪些能写、哪些直接拒绝、哪些要人审批——默认「没匹配到规则就允许」。

```python
from deepagents import FilesystemPermission, create_deep_agent


# Read-only agent: deny all writes
agent = create_deep_agent(
    model=model,
    backend=backend,
    permissions=[
        FilesystemPermission(
            operations=["write"],
            paths=["/**"],
            mode="deny",
        ),
    ],
)
```

| 覆盖                                                         | 不覆盖                                                       |
| ------------------------------------------------------------ | ------------------------------------------------------------ |
| 内置文件工具：`ls`、`read_file`、`glob`、`grep`、`write_file`、`edit_file`、`delete` | 自定义工具、MCP 工具（即使它们自己读盘）                     |
|                                                              | **Sandbox / `execute`**：shell 可访问任意路径，路径权限挡不住 |

**匹配规则：**

1. 按**声明顺序**从上到下
2. **第一条**同时匹配 operations + paths 的规则生效
3. 没有任何规则匹配 → **允许**（宽松默认）

路径会做规范化，减轻 .. 等穿越绕过

# Sandboxes

### Sandbox as tool

```
你的机器/服务器：LLM 循环、工具调度、API Key
        ↓  tool call
远程沙箱：read/write/execute 真正发生在这里
```

- Agent 逻辑在宿主机，命令在远程跑
- Key 不必进沙箱，迭代 agent 逻辑更方便

### Agent in sandbox

- 整个 agent 进程跑在容器/VM 里
- 通信与镜像要自己搭，更贴近「生产与本地一致」的部署

# Interpreters

Interpreters 是 Deep Agents 里的轻量可编程层：agent 在循环内写 JS/TS，由嵌入的 QuickJS 运行时执行，中间状态留在解释器里，只有最终结果回到模型上下文。它是「一次一次 tool call」和「完整 Sandbox」之间的中间方案。

- 普通 tool calling：模型每一步都选工具、看结果、再选下一步
- Sandbox：完整 OS + shell + 装包
- 在隔离的 JS 运行时里写循环/分支/Promise.all，可选择性地从代码里调**白名单工具（PTC）、子代理（Dynamic subagents）**

为什么需要它:

- 模型一轮里可以发出一批 tool call，但那批tool call在发出时就固定了，无法在「看到第 3 个结果后再决定第 4 个参数」。

Interpreter 把编排写进代码：

- 循环、重试、分支、并行
- 中间变量不进模型上下文 → 省 token、上下文更干净
- 确定性更强（例如对 100 个文件各派一个 subagent）

```
pip install -U "deepagents[quickjs]"
```

```python
from deepagents import create_deep_agent
from langchain_quickjs import CodeInterpreterMiddleware

agent = create_deep_agent(
    model="google_genai:gemini-3.6-flash",
    middleware=[CodeInterpreterMiddleware()],
)
```

agent 自己写代码并调用，你一般不直接调解释器

工作原理：

```
模型写 JS → 调用 eval
       ↓
QuickJS 在隔离上下文中执行
       ↓（可选）await tools.xxx(...) / task(...)
       ↓
主机执行真实工具，结果回解释器
       ↓
最后表达式 + console 输出 → 回到模型上下文
```

### Programmatic Tool Calling（PTC）

  ```python
  agent = create_deep_agent(
    model="openai:gpt-4o",
    middleware=[CodeInterpreterMiddleware(ptc=["web_search", "task"])], 
  )
  ```

需要显示指定可用工具，比如上面的：web_search、task。

### Dynamic subagents

怎么启用:

- 有 subagents
- 挂上 Code Interpreter 中间件

eg:

```python
from deepagents import create_deep_agent
from langchain_quickjs import CodeInterpreterMiddleware

agent = create_deep_agent(
    model="google_genai:gemini-3.6-flash",
    subagents=[{
        "name": "reviewer",
        "description": "Reviews code for security issues, citing lines and severity",
        "system_prompt": "You are a security-focused code reviewer. Report issues with line numbers and severity.",
    }],
    middleware=[CodeInterpreterMiddleware()],
)
```

# Event Streaming

Event Streaming（事件流）, 本质上是指：在 Deep Agent 执行过程中，把内部发生的各种事件实时暴露出来，而不是等 Agent 完整运行结束后一次性返回结果。

它主要用于构建类似 ChatGPT、Claude Code、Cursor 这种实时交互体验：用户可以看到：
- LLM 正在输出 token
- Agent 正在调用工具
- SubAgent 正在执行任务
- 文件正在读写
- 任务进度变化

```python
load_dotenv()

api_key = os.getenv("LLM_API_KEY").strip()
api_url = os.getenv("LLM_BASE_URL").strip() # Custom API URL for the OpenAI-compatible endpoint

model = ChatOpenAI(openai_api_key=api_key, openai_api_base=api_url, model="claude-opus-4-8", temperature=0.7, use_responses_api=False)

agent = create_deep_agent(
    model=model
)

stream = agent.stream_events(
    {
        "messages": [{"role": "user", "content": "Write me a haiku about the sea"}],
    },
    version="v3",
)

for message in stream.messages:
    print(message.text)

```

https://docs.langchain.com/oss/python/deepagents/event-streaming

# Skills

典型目录结构：

```
skills/
└── my-skill/
    ├── SKILL.md          # 必须：元数据 + 指令
    ├── scripts/          # 可选：可执行脚本
    ├── references/       # 可选：详细参考文档
    └── assets/           # 可选：模板、图片等资源
```

SKILL.md 格式示例：

```
---
name: web-research
description: 结构化的网页研究工作流，适用于需要全面搜集信息的任务
---

# Web Research Skill

## When to Use
- 用户要求研究某个主题
- 需要多源信息交叉验证时

## Instructions
1. ...
2. ...
```

```python
from deepagents import create_deep_agent

agent = create_deep_agent(
    skills=["./skills/", "~/.deepagents/agent/skills/"],
    # 其他参数...
)
```

# Memory

```python
from deepagents import create_deep_agent
from deepagents.backends import CompositeBackend, StateBackend, StoreBackend
from langgraph.store.memory import InMemoryStore

agent = create_deep_agent(
    memory=["/memories/AGENTS.md"],          # 始终加载的记忆文件
    skills=["/skills/"],                     # 可选：按需技能
    backend=CompositeBackend(
        default=StateBackend(),              # 临时文件
        routes={
            "/memories/": StoreBackend(...)  # 持久化记忆
        }
    ),
    store=InMemoryStore(),                   # 或真实持久化 Store
)
```

```python
from deepagents import create_deep_agent
from deepagents.backends import CompositeBackend, StateBackend, StoreBackend
from langgraph.store.memory import InMemoryStore

store = InMemoryStore()

agent = create_deep_agent(
    model="anthropic:claude-sonnet-4-6",
    store=store,
    backend=CompositeBackend(
        default=StateBackend(),
        routes={
            "/memories/": StoreBackend(namespace=lambda _rt: ("memories",)),
        },
    ),
    system_prompt="""When users tell you their preferences, save them to
    /memories/user_preferences.txt so you remember them in future conversations.""",
)
```

# Retrieval

| 架构            | 描述                                   | 控制力 | 灵活性 | 延迟       | 典型场景               |
| --------------- | -------------------------------------- | ------ | ------ | ---------- | ---------------------- |
| **2-Step RAG**  | 固定流程：先检索 → 再生成              | 高     | 低     | 低且可预测 | FAQ、文档问答机器人    |
| **Agentic RAG** | 代理自主决定「何时」「如何」检索       | 低     | 高     | 可变       | 多工具研究助手         |
| **Hybrid RAG**  | 结合两者，加入验证、重写、自我校正步骤 | 中     | 中     | 可变       | 需要质量校验的领域问答 |

# Context engineering

- 启动上下文要精简：Memory 只放始终相关的内容，细节放 Skills
- 重活交给子代理：多步、输出大的任务用 task 隔离
- 充分利用文件系统：大结果写文件，而不是塞进对话
- 明确告诉代理记忆结构：在 prompt 中说明 /memories/ 里有什么、如何使用
- 合理排除不用的工具：通过 harness profile 的 excluded_tools 减小基础 prompt

# Harness profiles

rofiles（配置文件/档案） 是一套用于针对特定模型（Model Spec）或模型提供商（Provider）定制智能体行为的机制

```python
from deepagents import (
    GeneralPurposeSubagentProfile,
    HarnessProfile,
    register_harness_profile,
)

register_harness_profile(
    "openai:gpt-5.5",
    HarnessProfile(
        system_prompt_suffix="Respond in under 100 words.",
        excluded_tools={"execute"},
        excluded_middleware={"SummarizationMiddleware"},
        general_purpose_subagent=GeneralPurposeSubagentProfile(enabled=False),
    ),
)
```

- system_prompt_suffix：追加在最终 system prompt 最后（主代理 + 子代理都会生效）
- excluded_tools：从工具列表中移除指定工具（例如隐藏 execute 或全部文件系统工具）
- excluded_middleware：排除某些默认中间件
- general_purpose_subagent：控制自动添加的通用子代理（是否启用、如何配置）

Profiles = 按模型自动生效的 harness 配置包，让你用同一套 create_deep_agent 代码，在不同模型上获得更优表现，而不用到处写 if-else。



# Subagents

主代理通过内置的 task 工具，把复杂或重型子任务交给拥有独立上下文窗口的子代理执行，子代理完成后只返回一份精炼结果，从而避免主代理的上下文被中间过程填满。

```python
from deepagents import create_deep_agent

research_subagent = {
    "name": "research-agent",                    # 必填，主代理用这个名字调用
    "description": "Used to research in-depth questions",  # 必填，主代理据此决定是否委托
    "system_prompt": "You are an expert researcher...",    # 必填，子代理自己的指令
    "tools": [internet_search],                  # 可选，覆盖继承的工具
    "model": "openai:gpt-5.5",                   # 可选，覆盖主代理模型
    "skills": ["/skills/research/"],             # 可选，独立 Skills
    "middleware": [...],                         # 可选
    "interrupt_on": {...},                       # 可选，人机协同
}

agent = create_deep_agent(
    model="google_genai:gemini-3.6-flash",
    subagents=[research_subagent],
)
```