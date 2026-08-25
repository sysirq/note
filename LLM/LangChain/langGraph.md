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

### Error Handling（错误处理）

error handler 在节点失败且所有重试耗尽后运行。它接收当前状态，可以使用命令更新它或将路由到不同的节点。这对于补偿流程（ Saga 模式）很有用，您希望优雅地恢复而不是终止整个图。

Pass `error_handler=` to [`add_node`](https://reference.langchain.com/python/langgraph/graph/state/StateGraph/add_node):

```python
from langgraph.errors import NodeError
from langgraph.types import Command, RetryPolicy
from langgraph.graph import StateGraph, START
from typing_extensions import TypedDict

class State(TypedDict):
    status: str

def reserve_inventory(state: State) -> State:
    return {"status": "reserved"}

def charge_payment(state: State) -> State:
    raise RuntimeError("payment timeout")

def payment_error_handler(state: State, error: NodeError) -> Command:
    return Command(
        update={"status": f"compensated_after_{error.node}: {error.error}"},
        goto="finalize",
    )

def finalize(state: State) -> State:
    return state

graph = (
    StateGraph(State)
    .add_node("reserve_inventory", reserve_inventory)
    .add_node(
        "charge_payment",
        charge_payment,
        retry_policy=RetryPolicy(max_attempts=3, retry_on=ConnectionError),
        error_handler=payment_error_handler,
    )
    .add_node("finalize", finalize)
    .add_edge(START, "reserve_inventory")
    .add_edge("reserve_inventory", "charge_payment")
    .compile()
)
```

- 可以更新 state，也可以用 Command 跳转到其他节点（适合 Saga / 补偿模式）

### Graph Defaults（全局默认）

代替在每次add_node调用中重复相同的retry_policy=、error_handler=、timeout=或cache_policy=，使用set_node_defaults在一个位置配置graph的全局默认值：

```python
graph = (
    StateGraph(State)
    .set_node_defaults(error_handler=default_error_handler)
    .add_node("step_a", step_a)                                     # uses default_error_handler
    .add_node("step_b", step_b, error_handler=custom_error_handler) # uses custom_error_handler
    .add_edge(START, "step_a")
    .compile()
)
```

- 节点级别的配置会覆盖默认值
- 子图不会继承父图的 defaults

# Event streaming

```python
run = graph.stream_events(
    input,
    version="v3"
)

for message in run.messages:
    for token in message.text:
        print(token)
```

# Interrupts

- interrupt() 函数：在节点任意位置调用，即可动态暂停图执行。
- 调用后发生的事情：
  - 图在当前位置挂起
  - 状态通过 checkpointer 持久化保存
  - 你传给 interrupt() 的值（任意 JSON 可序列化对象）会暴露给调用方
  - 图无限等待，直到你用 Command(resume=...) 恢复
- 与静态断点的区别：Interrupts 是动态、可条件触发的，写在业务逻辑里；静态断点是编译时固定的。

前提条件：

- 必须有 checkpointer（生产环境用持久化的，如数据库）
- 必须指定 thread_id（config={"configurable": {"thread_id": "xxx"}}）——它是持久化游标

需要注意的点：

- resume 不是从暂停那一行继续！而是重新执行整个 node。

eg:

```python
from langgraph.types import Command

stream_input = initial_input

while True:
    stream = graph.stream_events(stream_input, config=config, version="v3")

    # 实时流式输出 token
    for message in stream.messages:
        for token in message.text:
            print(token, end="", flush=True)

    if not stream.interrupted:
        final_state = stream.output
        break

    # 处理中断
    interrupt_info = stream.interrupts[0].value
    user_response = get_user_input(interrupt_info)
    stream_input = Command(resume=user_response)
```

# Time travel

本质是Checkpoint管理

### Replay

从某个历史 checkpoint 重新执行，该 checkpoint 之前的节点不重跑（结果已保存），之后的节点全部重执行（包括 LLM 调用、API、interrupt()）。

```python
from langgraph.graph import StateGraph, START
from langgraph.checkpoint.memory import InMemorySaver
from typing_extensions import TypedDict, NotRequired
from langchain_core.utils.uuid import uuid7

class State(TypedDict):
    topic: NotRequired[str]
    joke: NotRequired[str]


def generate_topic(state: State):
    return {"topic": "socks in the dryer"}


def write_joke(state: State):
    return {"joke": f"Why do {state['topic']} disappear? They elope!"}


checkpointer = InMemorySaver()
graph = (
    StateGraph(State)
    .add_node("generate_topic", generate_topic)
    .add_node("write_joke", write_joke)
    .add_edge(START, "generate_topic")
    .add_edge("generate_topic", "write_joke")
    .compile(checkpointer=checkpointer)
)

# Step 1: Run the graph
config = {"configurable": {"thread_id": str(uuid7())}}
result = graph.invoke({}, config)

print(result)

# Step 2: Find a checkpoint to replay from
history = list(graph.get_state_history(config))
# History is in reverse chronological order
for state in history:
    print(f"next={state.next}, checkpoint_id={state.config['configurable']['checkpoint_id']}")

# Step 3: Replay from a specific checkpoint
# Find the checkpoint before write_joke
before_joke = next(s for s in history if s.next == ("write_joke",))
replay_result = graph.invoke(None, before_joke.config)
# write_joke re-executes (runs again), generate_topic does not
print(result)
```

output:

```
{'topic': 'socks in the dryer', 'joke': 'Why do socks in the dryer disappear? They elope!'}
next=(), checkpoint_id=1f1a06d4-c8f9-6808-8002-87a314b38a78
next=('write_joke',), checkpoint_id=1f1a06d4-c8f8-6dae-8001-b654a242621b
next=('generate_topic',), checkpoint_id=1f1a06d4-c8f7-6666-8000-e2c5fa2a3f21
next=('__start__',), checkpoint_id=1f1a06d4-c8f5-6d3e-bfff-4f90d78ab670
{'topic': 'socks in the dryer', 'joke': 'Why do socks in the dryer disappear? They elope!'}
```

### Fork

从某个历史 checkpoint 分叉出新分支，并修改状态。用 update_state 创建新 checkpoint（原历史不受影响），然后从新分支继续执行。

```python
# Find checkpoint before write_joke
history = list(graph.get_state_history(config))
before_joke = next(s for s in history if s.next == ("write_joke",))

# Fork: update state to change the topic
fork_config = graph.update_state(
    before_joke.config,
    values={"topic": "chickens"},
)

# Resume from the fork — write_joke re-executes with the new topic
fork_result = graph.invoke(None, fork_config)
print(fork_result["joke"])  # A joke about chickens, not socks
```

# Memory

