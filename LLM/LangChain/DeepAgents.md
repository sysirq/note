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

