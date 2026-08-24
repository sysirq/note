# Workflows and agents

| 类型                    | 特点                             | 适用场景             |
| ----------------------- | -------------------------------- | -------------------- |
| **Workflows（工作流）** | 路径预先设定，按固定顺序执行     | 任务步骤明确、可预测 |
| **Agents（智能体）**    | 动态决策，自己决定流程和工具使用 | 问题与解决方案不确定 |

### LLM 增强手段

构建工作流或智能体时，常用三种增强方式：

- 结构化输出（with_structured_output）：让 LLM 返回指定格式的数据（如 Pydantic 模型）
- 工具调用（bind_tools）：让 LLM 能调用外部函数
- 短期记忆（Short-term memory）

![LLM augmentations](images/augmented_llm.png)

### 常见工作流模式

- Prompt Chaining（提示链）

  多个 LLM 调用串联，前一个输出作为后一个输入

  适合：可拆分成明确步骤的任务（翻译、内容校验、逐步润色）

- Parallelization（并行化）

  多个 LLM 同时执行不同子任务，或对同一任务多次运行

  优点：提升速度 或 提高结果置信度

- Routing（路由）

  先用 LLM 判断输入类型，再路由到对应的专门处理节点

  适合：需要根据不同情况走不同流程的场景

- Orchestrator-Worker（编排器-工作者）

  编排器：拆分任务、分配子任务

  工作者：并行执行具体子任务

  合成器：汇总所有结果

  核心 API：Send（动态创建 worker 并发送不同输入）

- Evaluator-Optimizer（评估器-优化器）

​	生成器生成内容 → 评估器打分并给反馈 → 不合格则循环优化

​	适合：有明确质量标准、需要迭代改进的任务（翻译、笑话优化等）

### Agents

本质是：LLM + 工具的循环决策

# Checkpointers

 **每次 Super-step 结束时**，如果图配置了 Checkpointer（如 MemorySaver, SqliteSaver 等），LangGraph 就会自动拍摄当前全局状态的快照，这就是一个 **Checkpoint**。

 一个 Super-step 代表了图在当前状态下，**所有准备好运行的节点（Nodes）的集合**

- 如果图的逻辑（即边/Edges）决定了只有一个节点应该运行，那么这个 Super-step 就只包含这一个节点。
-  如果图使用了分支（Fan-out），导致多个节点可以同时运行，那么**所有这些并行的节点都在同一个 Super-step 中并发执行**。
-  从一组节点过渡到下一组节点，就标志着一个 Super-step 的结束和下一个 Super-step 的开始。

### Get and update state

- Get state

```python
# get the latest state snapshot
config = {"configurable": {"thread_id": "1"}}
graph.get_state(config)

# get a state snapshot for a specific checkpoint_id
config = {"configurable": {"thread_id": "1", "checkpoint_id": "1ef663ba-28fe-6528-8002-5a559208592c"}}
graph.get_state(config)
```

- Get state history：取给定线程的图的完整执行历史记录。

```python
config = {"configurable": {"thread_id": "1"}}
list(graph.get_state_history(config)) # checkpoints将按时间顺序排列，最近的checkpoint /StateSnapshot 将在列表的第一位。
```

### Checkpointer libraries

- 内存版(开发测试)

  ```python
  from langgraph.checkpoint.memory import InMemorySaver 
  
  checkpointer = InMemorySaver()
  graph = builder.compile(checkpointer=checkpointer)
  ```

- SQLite（本地持久化）

  ```python
  from langgraph.checkpoint.sqlite import SqliteSaver # pip install langgraph-checkpoint-sqlite
  
  with SqliteSaver.from_conn_string("checkpoints.db") as checkpointer:
      graph = builder.compile(checkpointer=checkpointer)
  ```

- PostgreSQL（生产推荐）

  ```python
  from langgraph.checkpoint.postgres import PostgresSaver # pip install langgraph-checkpoint-postgres
  
  DB_URI = "postgresql://user:password@localhost:5432/langgraph"
  
  with PostgresSaver.from_conn_string(DB_URI) as checkpointer:
      checkpointer.setup()          # 首次使用必须运行，创建表
      graph = builder.compile(checkpointer=checkpointer)
  ```

# Stores

存储任意键值数据，可从任何线程访问。

- 记忆用 namespace（元组，如 (user_id, "memories")）组织。

### 核心操作

- store.put(namespace, key, value)：存记忆
- store.search(namespace)：取记忆（可加 limit、offset 分页），返回的是 Item 对象，包含 value、key、namespace、created_at、updated_at。

eg:

```python
from langgraph.store.memory import InMemoryStore
import uuid

store = InMemoryStore()

user_id = "1"
namespace_for_memory = (user_id, "memories")

memory_id = str(uuid.uuid4())

memory = {"food_preference" : "I like pizza"}
store.put(namespace_for_memory, memory_id, memory)

memories = store.search(namespace_for_memory)

print(memories[-1].dict())
```

output:

```
{'namespace': ['1', 'memories'], 'key': 'b4142aca-91ec-4cee-b529-05f03c9ce7e5', 'value': {'food_preference': 'I like pizza'}, 'created_at': '2026-08-24T08:58:18.261816+00:00', 'updated_at': '2026-08-24T08:58:18.261958+00:00', 'score': None}
```

类似结构：

```
Store

user_123
 |
 └── memories
        |
        ├── memory_001
        │       |
        │       {
        │          food:pizza
        │       }
        │
        └── memory_002
                {
                  language:Chinese
                }

```



### 语义搜索

- 配置 embedding 模型后，可以用自然语言查询记忆
- 可控制哪些字段被嵌入（fields 或 put 时的 index 参数）。
- 支持不嵌入某些数据（index=False）。

Eg:

```python
from langchain.embeddings import init_embeddings

store = InMemoryStore(
    index={
        "embed": init_embeddings("openai:text-embedding-3-small"),  # Embedding provider
        "dims": 1536,                              # Embedding dimensions
        "fields": ["food_preference", "$"]              # Fields to embed
    }
)

# Store with specific fields to embed
store.put(
    namespace_for_memory,
    str(uuid.uuid4()),
    {
        "food_preference": "I love Italian cuisine",
        "context": "Discussing dinner plans"
    },
    index=["food_preference"]  # Only embed "food_preferences" field
)

# Store without embedding (still retrievable, but not searchable)
store.put(
    namespace_for_memory,
    str(uuid.uuid4()),
    {"system_info": "Last updated: 2024-01-01"},
    index=False
)

# Find memories about food preferences
# (This can be done after putting memories into the store)
memories = store.search(
    namespace_for_memory,
    query="What does the user like to eat?",
    limit=3  # Return top 3 matches
)
```

### 在 LangGraph 中使用

```python
from dataclasses import dataclass
from langgraph.runtime import Runtime

@dataclass
class Context:
    user_id: str

async def call_model(state: MessagesState, runtime: Runtime[Context]):
    # Get the user id from the runtime context
    user_id = runtime.context.user_id

    # Namespace the memory
    namespace = (user_id, "memories")

    # Search based on the most recent message
    memories = await runtime.store.asearch(
        namespace,
        query=state["messages"][-1].content,
        limit=3
    )
    info = "\n".join([d.value["memory"] for d in memories])

    # ... Use memories in the model call
```

如果您创建一个新的线程，只要用户ID相同，您仍然可以访问相同的记忆。

# Fault Tolerance（容错机制）

### Retries（重试）

```python
from langgraph.types import RetryPolicy, default_retry_on

def custom_retry_on(exc: BaseException) -> bool:
    if isinstance(exc, MyCustomError):
        return False
    return default_retry_on(exc)

builder.add_node(
    "call_api",
    call_api,
    retry_policy=RetryPolicy(max_attempts=3, retry_on=custom_retry_on),
)
```

关键参数：

- max_attempts：总尝试次数（默认 3）
- initial_interval / backoff_factor / max_interval：指数退避
- jitter：是否添加随机抖动
- retry_on：哪些异常才重试（默认会跳过 ValueError、TypeError 等编程错误，HTTP 库只重试 5xx），或一个返回 True 的可调用对象，用于重试异常。

节点里可以通过 runtime.execution_info.node_attempt 知道当前是第几次尝试，方便做 fallback。

### Timeouts（超时）

add_node中的timeout=参数限制了单个节点尝试运行的时间。传递一个数字（秒）、一个timedelta或一个TimeoutPolicy，用于设置单独的运行和空闲限制：

```python
from datetime import timedelta
from langgraph.types import TimeoutPolicy

# Simple wall-clock cap
builder.add_node("call_model", call_model, timeout=60)
builder.add_node("call_model", call_model, timeout=timedelta(minutes=2))

# Separate run and idle limits
builder.add_node(
    "call_model",
    call_model,
    timeout=TimeoutPolicy(run_timeout=120, idle_timeout=30),
)
```

- 只支持 async 节点（sync 节点会在 compile 时报错）
- 两种超时：
	- run_timeout: 总时间限制，eg:最多运行30秒
	
	- idle_timeout: 空闲时间限制，有进度信号就重置计时器，进度信号包括：写 state、stream 输出、子任务、LangChain 回调事件等。也可以用 runtime.heartbeat() 手动保活（需要设置refresh_on="heartbeat"）。
- 超时后抛 NodeTimeoutError，这次 attempt 的写入会被清除，然后交给 RetryPolicy 决定是否重试。