# Agents

在 LangChain 中，Agent（智能体） 是一个模型在循环中不断调用工具，直到完成给定任务的过程。围绕这个循环的所有东西（提示词、工具、以及塑造模型行为的中间件）统称为 Harness（运行框架）。

Agent = Model + Harness

核心入口是 langchain.agents 中的 create_agent。

```python
from langchain.agents import create_agent

agent = create_agent(model="google_genai:gemini-3.6-flash", tools=tools)
```

- system_prompt（字符串或 SystemMessage）
- response_format（用于结构化输出，例如 Pydantic 模型）
- checkpointer（用于对话记忆）
- context_schema + context（用于每次运行的额外数据）
- name（在多智能体系统中标识该 agent）
- middleware（用于高级行为控制）

# Model

### 初始化模型

```
pip install -U "langchain[openai]"
```

```python
from langchain.chat_models import init_chat_model
from dotenv import load_dotenv
load_dotenv()

api_key = os.getenv("API_KEY")
api_url = os.getenv("API_URL")

model = init_chat_model(api_key=api_key, base_url=api_url,model="gpt-5.6-sol")
```

- init_chat_model 参数：

| 参数               | 类型            | 说明                                           |
| ------------------ | --------------- | ---------------------------------------------- |
| **temperature**    | `float`         | 控制输出随机性。值越小越确定，越大越有创造性。 |
| **max_tokens**     | `int`           | 限制输出最大 token 数。有效控制输出的长度。    |
| **timeout**        | `int` / `float` | 请求超时时间（秒）。                           |
| **max_retries**    | `int`           | 失败重试次数（默认通常为 6）。                 |
| **api_key**        | `str`           | API 密钥（也可用环境变量）。                   |
| **base_url**       | `str`           | 自定义 API 端点。                              |
| **model**          | `str`           | 模型名称。                                     |
| **model_provider** | `str`           | 单独指定提供商。e g: model_provider="openai",  |

### 调用

- invoke

```python
response = model.invoke("Why do parrots have colorful feathers?")
print(response)

################################################################################################

conversation = [
    {"role": "system", "content": "You are a helpful assistant that translates English to French."},
    {"role": "user", "content": "Translate: I love programming."},
    {"role": "assistant", "content": "J'adore la programmation."},
    {"role": "user", "content": "Translate: I love building applications."}
]

response = model.invoke(conversation)
print(response)  # AIMessage("J'adore créer des applications.")

################################################################################################

from langchain.messages import HumanMessage, AIMessage, SystemMessage

conversation = [
    SystemMessage("You are a helpful assistant that translates English to French."),
    HumanMessage("Translate: I love programming."),
    AIMessage("J'adore la programmation."),
    HumanMessage("Translate: I love building applications.")
]

response = model.invoke(conversation)
print(response)  # AIMessage("J'adore créer des applications.")
```

- Stream

调用stream()返回一个迭代器，它按产生顺序输出数据块。您可以使用循环实时处理每个数据块：

```python
for chunk in model.stream("Why do parrots have colorful feathers?"):
    print(chunk.text, end="|", flush=True)
```

output:

```
Par|rots| have| colorful| feathers| for| several| reasons|:

|-| **|Communication| and| mate| selection|:**| Bright| colors| can| signal| health|,| age|,| species|,| and| reproductive| fitness|.| In| some| parro|ts|,| males| and| females| use| color| differences| to| recognize| suitable| mates|.
|-| **|Species| recognition|:**| Dist|inct|ive| patterns| help| parro|ts| identify| members| of| their| own| species|,| especially| in| dense| forests| or| large| fl|ocks|.
|-| **|Cam|ouflage|:**| Although| vivid| to| us|,| green| feathers| can| blend| into| leafy| environments|.| Other| colors| may| break| up| the| bird|’s| outline| among| flowers|,| fruits|,| and| foliage|.
|-| **|Fe|ather| structure| and| pigments|:**| Yellow|,| red|,| and| orange| colors| mostly| come| from| pigments|,| while| blue| and| some| green| colors| are| produced| by| microscopic| structures| that| scatter| light|.| Par|rots| also| have| unusual| pigments| called| **|ps|itt|ac|of|ul|v|ins|**,| which| create| many| of| their| red|,| orange|,| and| yellow| hues|.
|-| **|Individual| condition|:**| Feather| brightness| can| sometimes| reflect| nutrition| and| overall| health|.

|So|,| par|rot| coloration| is| a| combination| of| genetics|,| feather| chemistry|,| light|-sc|attering| structures|,| and| evolutionary| pressures|.|||%      
```

- Batch

批量请求处理

```python
responses = model.batch([
    "Why do parrots have colorful feathers?",
    "How do airplanes fly?",
    "What is quantum computing?"
])
for response in responses:
    print(response)
    
################################################################################################
    
for response in model.batch_as_completed([
    "Why do parrots have colorful feathers?",
    "How do airplanes fly?",
    "What is quantum computing?"
]):
    print(response)
```

### 工具调用

为了使定义的工具可供模型使用，必须通过bind_tools进行绑定。

```python
from langchain.tools import tool

@tool
def get_weather(location: str) -> str:
    """Get the weather at a location."""
    return f"It's sunny in {location}."


model_with_tools = model.bind_tools([get_weather])

response = model_with_tools.invoke("What's the weather like in Boston?")
for tool_call in response.tool_calls:
    # View tool calls made by the model
    print(f"Tool: {tool_call['name']}")
    print(f"Args: {tool_call['args']}")
```

### 结构化输出

```python
from pydantic import BaseModel, Field

class Movie(BaseModel):
    """A movie with details."""
    title: str = Field(description="The title of the movie")
    year: int = Field(description="The year the movie was released")
    director: str = Field(description="The director of the movie")
    rating: float = Field(description="The movie's rating out of 10")

model_with_structure = model.with_structured_output(Movie)
response = model_with_structure.invoke("Provide details about the movie Inception")
print(response)  # Movie(title="Inception", year=2010, director="Christopher Nolan", rating=8.8)
```

# Messages

| 类型               | 角色      | 用途                     | 关键属性                                                   |
| ------------------ | --------- | ------------------------ | ---------------------------------------------------------- |
| **SystemMessage**  | system    | 设定模型行为、角色、规则 | content                                                    |
| **HumanMessage**   | user      | 用户输入                 | content（支持多模态）                                      |
| **AIMessage**      | assistant | 模型输出                 | content、**tool_calls**、usage_metadata、response_metadata |
| **ToolMessage**    | tool      | 工具执行结果             | content、**tool_call_id**（必须匹配）、name、artifact      |
| **AIMessageChunk** | assistant | 流式输出的片段           | 支持 `+` 运算符合并成完整 AIMessage                        |

```python
messages = [
    {"role": "system", "content": "You are a poetry expert"},
    {"role": "user", "content": "Write a haiku about spring"},
    {"role": "assistant", "content": "Cherry blossoms bloom..."}
]
response = model.invoke(messages)
```

```python
from langchain.messages import SystemMessage, HumanMessage, AIMessage

messages = [
    SystemMessage("You are a poetry expert"),
    HumanMessage("Write a haiku about spring"),
    AIMessage("Cherry blossoms bloom...")
]
response = model.invoke(messages)
print(type(response))   # <class 'langchain_core.messages.ai.AIMessage'>
```

# Tools

### 定义tool

```python
from langchain.tools import tool

@tool
def search_database(query: str, limit: int = 10) -> str:
    """Search the customer database for records matching the query.

    Args:
        query: Search terms to look for
        limit: Maximum number of results to return
    """
    return f"Found {limit} results for '{query}'"
model_with_tools = model.bind_tools([search_database])
```

类型提示是必需的，因为它们定义了工具的输入模式。文档字符串应提供信息且简洁，以帮助模型理解工具的目的。

# Short-term memory

为添加短期记忆（线程级持久化）到代理，您需要在创建代理时指定checkpointer，（同时也需要指定configurable）。

```python
from langchain.agents import create_agent
from langgraph.checkpoint.memory import InMemorySaver  


def get_user_info() -> str:
    """Look up information about the current user."""
    return "No user profile on file."


agent = create_agent(
    model="google_genai:gemini-3.6-flash",
    tools=[get_user_info],
    checkpointer=InMemorySaver(),
)

thread_config = {"configurable": {"thread_id": "1"}}
response = agent.invoke(
    {"messages": [{"role": "user", "content": "Hi! My name is Bob."}]},
    thread_config,
)["messages"][-1].content

print(response)  # "Hi Bob! Nice to see you here. How are you doing?"

response = agent.invoke(
    {"messages": [{"role": "user", "content": "What's my name?"}]},
    thread_config,
)["messages"][-1].content

print(response)  # "You are Bob!"
```

在生产环境中，使用由数据库支持的checkpointer：

```python
from langchain.agents import create_agent
from langgraph.checkpoint.postgres import PostgresSaver  

def get_user_info() -> str:
    """Look up information about the current user."""
    return "No user profile on file."

DB_URI = "postgresql://postgres:postgres@localhost:5432/postgres?sslmode=disable"
with PostgresSaver.from_conn_string(DB_URI) as checkpointer:
    checkpointer.setup() # auto create tables in PostgreSQL
    agent = create_agent(
        "gpt-5.5",
        tools=[get_user_info],
        checkpointer=checkpointer,
    )
```

### 防止超出LLM上下文空间的方法

###### Trim messages

要在agent中裁剪历史消息，使用@before_model中间件装饰器：

```python
from langchain.messages import RemoveMessage
from langgraph.graph.message import REMOVE_ALL_MESSAGES
from langgraph.checkpoint.memory import InMemorySaver
from langchain.agents import create_agent, AgentState
from langchain.agents.middleware import before_model
from langgraph.runtime import Runtime
from langchain_core.runnables import RunnableConfig
from typing import Any


@before_model
def trim_messages(state: AgentState, runtime: Runtime) -> dict[str, Any] | None:
    """Keep only the last few messages to fit context window."""
    messages = state["messages"]

    if len(messages) <= 3:
        return None  # No changes needed

    first_msg = messages[0]
    recent_messages = messages[-3:] if len(messages) % 2 == 0 else messages[-4:]
    new_messages = [first_msg] + recent_messages

    return {
        "messages": [
            RemoveMessage(id=REMOVE_ALL_MESSAGES),
            *new_messages
        ]
    }

agent = create_agent(
    "gpt-5.5",
    tools=[...],
    middleware=[trim_messages],
    checkpointer=InMemorySaver(),
)

config: RunnableConfig = {"configurable": {"thread_id": "1"}}

agent.invoke({"messages": "hi, my name is bob"}, config)
agent.invoke({"messages": "write a short poem about cats"}, config)
agent.invoke({"messages": "now do the same but for dogs"}, config)
final_response = agent.invoke({"messages": "what's my name?"}, config)

final_response["messages"][-1].pretty_print()
"""
================================== Ai Message ==================================

Your name is Bob. You told me that earlier.
If you'd like me to call you a nickname or use a different name, just say the word.
"""
```

###### delete messages

```python
from langchain.messages import RemoveMessage  

def delete_messages(state):
    messages = state["messages"]
    if len(messages) > 2:
        # remove the earliest two messages
        return {"messages": [RemoveMessage(id=m.id) for m in messages[:2]]}
```

###### Summarize messages

```python
from langchain.agents import create_agent
from langchain.agents.middleware import SummarizationMiddleware
from langgraph.checkpoint.memory import InMemorySaver
from langchain_core.runnables import RunnableConfig


checkpointer = InMemorySaver()

agent = create_agent(
    model="gpt-5.5",
    tools=[...],
    middleware=[
        SummarizationMiddleware(
            model="gpt-5.4-mini",
            trigger=("tokens", 4000),
            keep=("messages", 20)
        )
    ],
    checkpointer=checkpointer,
)

config: RunnableConfig = {"configurable": {"thread_id": "1"}}
agent.invoke({"messages": "hi, my name is bob"}, config)
agent.invoke({"messages": "write a short poem about cats"}, config)
agent.invoke({"messages": "now do the same but for dogs"}, config)
final_response = agent.invoke({"messages": "what's my name?"}, config)

final_response["messages"][-1].pretty_print()
"""
================================== Ai Message ==================================

Your name is Bob!
"""
```

### Access Memory

###### 在工具中访问短期记忆

eg: 访问 user_id

```python
from langchain.agents import create_agent, AgentState
from langchain.tools import tool, ToolRuntime


class CustomState(AgentState):
    user_id: str

@tool
def get_user_info(
    runtime: ToolRuntime
) -> str:
    """Look up user info."""
    user_id = runtime.state["user_id"]
    return "User is John Smith" if user_id == "user_123" else "Unknown user"

agent = create_agent(
    model="gpt-5-nano",
    tools=[get_user_info],
    state_schema=CustomState,
)

result = agent.invoke({
    "messages": "look up user information",
    "user_id": "user_123"
})
print(result["messages"][-1].content)
# > User is John Smith.
```

###### 在工具中写入短期记忆

```python
from langchain.tools import tool, ToolRuntime
from langchain_core.runnables import RunnableConfig
from langchain.messages import ToolMessage
from langchain.agents import create_agent, AgentState
from langgraph.types import Command
from pydantic import BaseModel


class CustomState(AgentState):
    user_name: str

class CustomContext(BaseModel):
    user_id: str

@tool
def update_user_info(
    runtime: ToolRuntime[CustomContext, CustomState],
) -> Command:
    """Look up and update user info."""
    user_id = runtime.context.user_id
    name = "John Smith" if user_id == "user_123" else "Unknown user"
    return Command(update={
        "user_name": name,
        # update the message history
        "messages": [
            ToolMessage(
                "Successfully looked up user information",
                tool_call_id=runtime.tool_call_id
            )
        ]
    })

@tool
def greet(
    runtime: ToolRuntime[CustomContext, CustomState]
) -> str | Command:
    """Use this to greet the user once you found their info."""
    user_name = runtime.state.get("user_name", None)
    if user_name is None:
       return Command(update={
            "messages": [
                ToolMessage(
                    "Please call the 'update_user_info' tool it will get and update the user's name.",
                    tool_call_id=runtime.tool_call_id
                )
            ]
        })
    return f"Hello {user_name}!"

agent = create_agent(
    model="gpt-5-nano",
    tools=[update_user_info, greet],
    state_schema=CustomState,
    context_schema=CustomContext,
)

agent.invoke(
    {"messages": [{"role": "user", "content": "greet the user"}]},
    context=CustomContext(user_id="user_123"),
)
```

###### create dynamic prompts

```python
from langchain.agents.middleware import dynamic_prompt, ModelRequest

@dynamic_prompt
def dynamic_system_prompt(request: ModelRequest) -> str:
    user_name = request.runtime.context["user_name"]
    system_prompt = f"You are a helpful assistant. Address the user as {user_name}."
    return system_prompt

```

###### 在访问模型前访问

```
from langchain.agents.middleware import before_model

@before_model
def trim_messages(state: AgentState, runtime: Runtime) -> dict[str, Any] | None:
    """Keep only the last few messages to fit context window."""
    messages = state["messages"]

```

###### 在访问模型后访问

```
from langchain.agents.middleware import after_model

@after_model
def validate_response(state: AgentState, runtime: Runtime) -> dict | None:
    """Remove messages containing sensitive words."""
    STOP_WORDS = ["password", "secret"]
```

# Middleware

### Prebuilt middleware

| 中间件                    | 核心功能                                                     |
| ------------------------- | ------------------------------------------------------------ |
| **Summarization**         | 接近 token 限制时自动总结对话历史，保留最近消息，压缩旧上下文 |
| **Human-in-the-loop**     | 在工具调用前暂停，等待人类审批 / 编辑 / 拒绝（需 checkpointer） |
| **Model call limit**      | 限制模型调用次数（thread / run 级别），防止无限循环或成本失控 |
| **Tool call limit**       | 限制工具调用次数（全局或特定工具，支持 thread / run 限制）   |
| **Model fallback**        | 主模型失败时自动切换到备用模型                               |
| **PII detection**         | 检测并处理个人身份信息（email、信用卡等），支持 redact / mask / hash / block，可自定义检测器 |
| **To-do list**            | 给 agent 增加任务规划与跟踪能力（自动提供 `write_todos` 工具） |
| **LLM tool selector**     | 用另一个 LLM 先筛选相关工具，再交给主模型，减少无关工具干扰  |
| **Tool error**            | 捕获工具执行异常，转为错误消息给模型，让其可恢复             |
| **Tool retry**            | 工具调用失败时自动重试（指数退避）                           |
| **Model retry**           | 模型调用失败时自动重试（指数退避）                           |
| **LLM tool emulator**     | 用 LLM 模拟工具执行结果，便于测试 / 原型开发                 |
| **Context editing**       | 管理上下文，清理旧的工具输出，保留最近 N 个结果              |
| **Provider tool search**  | 把部分工具延迟到提供商服务端搜索（目前支持 Anthropic / OpenAI 部分模型） |
| **Shell tool**            | 给 agent 暴露持久 shell 会话，执行命令（需注意安全策略）     |
| **File search**           | 提供 Glob / Grep 等文件系统搜索工具                          |
| **Filesystem**            | 给 agent 提供文件系统，用于存储上下文和长期记忆              |
| **Subagent**              | 支持生成子 agent                                             |
| **Rubric grading (Beta)** | 用 LLM-as-a-judge 按评分标准评估并迭代，直到满足要求         |

### Custom middleware

| 类型                       | 钩子                                                     | 运行时机              | 适用场景                   |
| -------------------------- | -------------------------------------------------------- | --------------------- | -------------------------- |
| **Node-style**（顺序执行） | `before_agent` `before_model` `after_model``after_agent` | 在特定执行点顺序运行  | 日志、验证、状态更新       |
| **Wrap-style**（包装执行） | `wrap_model_call` `wrap_tool_call`                       | 围绕每次模型/工具调用 | 重试、缓存、转换、短路控制 |

# Runtime

create_agent 底层运行在 LangGraph 的 Runtime 之上，Runtime 对象提供了一次 agent 调用所需的关键上下文和依赖。

Runtime包含的信息：

- Context：静态信息（如 user id、数据库连接、其他依赖），用于依赖注入
- Store：BaseStore 实例，用于长期记忆
- Stream writer：用于通过 "custom" 流模式推送自定义信息
- Execution info：当前执行身份与重试信息（thread ID、run ID、attempt number）
- Server info：在 LangGraph Server 上运行时的服务端元数据（assistant ID、graph ID、已认证用户）

访问方式：

```python
@dataclass
class Context:
    user_name: str

agent = create_agent(
    model="gpt-5-nano",
    tools=[...],
    context_schema=Context
)

@dynamic_prompt
def dynamic_system_prompt(request: ModelRequest) -> str:
    user_name = request.runtime.context.user_name
    return f"You are a helpful assistant. Address the user as {user_name}.

agent.invoke(
    {"messages": [{"role": "user", "content": "What's my name?"}]},
    context=Context(user_name="John Smith")
)
```

# Context engineering

**Context Engineering in Agents（LangChain 文档核心总结）**

### 核心观点
构建可靠 Agent 的最大难点不是模型本身不够强，而是**没有把正确的上下文以正确的格式传给 LLM**。  
**Context Engineering** 就是：把正确的信息 + 工具 + 格式提供给模型，让它能可靠完成任务。这是 AI Engineer 的核心工作。

### Agent 循环
1. **Model Call**：带着 prompt 和工具调用 LLM，返回最终回复或工具请求  
2. **Tool Execution**：执行工具并返回结果  

循环直到模型决定结束。

### 三类可控制的上下文

| 类型 | 控制什么 | 瞬态 / 持久 |
|------|----------|-------------|
| **Model Context** | 进入模型的内容（System Prompt、Messages、Tools、Model、Response Format） | 瞬态 |
| **Tool Context** | 工具能读/写的内容（State、Store、Runtime Context） | 持久 |
| **Life-cycle Context** | 模型调用与工具执行之间的逻辑（摘要、护栏、日志等） | 持久 |

**瞬态**：只影响当前这一次模型调用，不改变 State  
**持久**：写入 State / Store，后续轮次都能看到

### 三大数据源

| 数据源 | 别名 | 作用域 | 典型用途 |
|--------|------|--------|----------|
| **Runtime Context** | 静态配置 | 单次对话 | User ID、API Key、权限、环境配置 |
| **State** | 短期记忆 | 单次对话 | 当前消息、上传文件、认证状态、工具结果 |
| **Store** | 长期记忆 | 跨对话 | 用户偏好、写作风格、历史洞察 |

### Model Context（控制模型看到什么）

通过 **middleware**（`@dynamic_prompt` 和 `@wrap_model_call`）动态调整：

- **System Prompt**：根据消息数量、用户偏好（Store）、角色/环境（Runtime Context）动态生成
- **Messages**：注入文件上下文、写作风格、合规规则等（默认瞬态）
- **Tools**：按认证状态、用户偏好、角色权限动态过滤可用工具
- **Model**：根据对话长度、用户偏好、成本层级动态切换模型
- **Response Format**：根据对话阶段、用户角色返回不同结构化输出（Pydantic Schema）

### Tool Context（工具的读写）

工具既能**读**也能**写**：

- **读**：State（当前状态）、Store（长期记忆）、Runtime Context（配置）
- **写**：用 `Command` 更新 State；直接 `store.put()` 写入长期记忆

### Life-cycle Context（生命周期中间件）

在模型调用和工具执行之间插入逻辑，可：
- 更新上下文（持久修改 State/Store）
- 跳转生命周期步骤

最常见例子：**SummarizationMiddleware**  
当 token 超限时自动摘要旧消息，**永久替换** State 中的历史，只保留最近消息。

### 最佳实践
1. 从简单静态开始，按需加动态
2. 一次只加一个 context engineering 功能，增量测试
3. 监控 token、延迟、调用次数
4. 优先使用内置中间件
5. 明确区分瞬态（单次调用）与持久（写入 State）
6. 把上下文策略写清楚

**底层机制**：LangChain 的 **Middleware** 是实现 Context Engineering 的核心手段，允许在 Agent 生命周期任意步骤挂钩，更新上下文或跳转流程。


# MCP(Model Context Protocol)

**Model Context Protocol (MCP) — LangChain 文档总结**

MCP 是一个开放协议，用于标准化应用程序如何向 LLM 提供工具和上下文。LangChain 通过 `langchain-mcp-adapters` 库让 Agent 直接使用 MCP 服务器上定义的工具。

### 1. 快速开始

安装：
```bash
pip install langchain-mcp-adapters
```

核心类：`MultiServerMCPClient`（默认**无状态**，每次工具调用都会新建 Session）。

示例：连接多个 MCP 服务器（stdio + HTTP），获取工具后创建 Agent：

```python
from langchain_mcp_adapters.client import MultiServerMCPClient
from langchain.agents import create_agent

client = MultiServerMCPClient({
    "math": {
        "transport": "stdio",
        "command": "python",
        "args": ["/path/to/math_server.py"],
    },
    "weather": {
        "transport": "http",
        "url": "http://localhost:8000/mcp",
    }
})
tools = await client.get_tools()
agent = create_agent("claude-sonnet-4-6", tools)
```

### 2. 自定义 MCP 服务器

使用 **FastMCP** 快速创建：

```python
from fastmcp import FastMCP

mcp = FastMCP("Math")

@mcp.tool()
def add(a: int, b: int) -> int:
    """Add two numbers"""
    return a + b

if __name__ == "__main__":
    mcp.run(transport="stdio")
```

### 3. 传输方式（Transports）

| 类型 | 说明 | 特点 |
|------|------|------|
| **HTTP**（streamable-http） | 远程服务器，支持 headers / 自定义 Auth | 适合远程部署 |
| **stdio** | 启动本地子进程通信 | 本地工具常用，本身有状态，但 MultiServerMCPClient 默认仍按次创建 Session |

### 4. 有状态会话（Stateful Sessions）

默认每次工具调用都是新 Session。需要持久 Session 时：

```python
async with client.session("server_name") as session:
    tools = await load_mcp_tools(session)
    agent = create_agent(..., tools)
```

### 5. 核心功能

#### Tools
- `client.get_tools()` 获取工具并直接传给 Agent。
- 工具错误默认以 `status="error"` 的 ToolMessage 返回给模型（不抛异常），方便 Agent 重试。
- 支持 **Structured Content**（结构化数据放在 `artifact` 中）。
- 支持 **Multimodal** 内容（图片 + 文本），通过 `content_blocks` 统一访问。

#### Resources
- 暴露文件、数据库记录等数据，转换为 LangChain `Blob`。
- `client.get_resources()` 或 `load_mcp_resources(session)`。

#### Prompts
- 可复用的提示模板，转换为消息列表。
- `client.get_prompt(server_name, prompt_name, arguments=...)`。

### 6. 高级功能

#### Tool Interceptors（拦截器）
MCP 服务器无法直接访问 LangGraph 的 Runtime Context / State / Store。**拦截器**弥补这个缺口，提供类似中间件的能力：

- 注入用户上下文、API Key
- 读取 Store 偏好做个性化
- 根据 State 做权限检查
- 修改请求参数 / Headers
- 返回 `Command` 更新状态或跳转
- 重试、限流、日志等

拦截器按“洋葱模型”叠加（列表第一个是最外层）。

#### 其他高级能力
- **Progress Notifications**：监听长任务进度。
- **Logging**：接收服务器日志。
- **Elicitation**：服务器在工具执行中途主动向用户请求额外输入（客户端通过回调处理 accept / decline / cancel）。

### 7. 关键要点总结

- **默认无状态**，需要持久上下文时用 `client.session()`。
- 工具、资源、提示都能无缝接入 LangChain Agent。
- **Interceptors** 是连接 MCP 与 LangGraph Runtime（State / Store / Context）的核心桥梁。
- 支持结构化输出、多模态、进度、日志和交互式输入（Elicitation）。

整体上，MCP 让你把外部工具/数据源标准化，LangChain 的 adapters 再把它们无缝变成 Agent 可用的 Tools / Resources / Prompts。

# Long-term Memory

**Long-term Memory（长期记忆）— LangChain 文档总结**

长期记忆让 Agent 能够**跨对话、跨会话**存储和回忆信息。  
与短期记忆（Short-term Memory，绑定到单个 thread）不同，长期记忆持久存在，随时可被召回。

它建立在 **LangGraph Store** 之上，数据以 JSON 文档形式存储，按 **namespace + key** 组织。

### 1. 基本用法

创建 Store 并传给 `create_agent`：

```python
from langchain.agents import create_agent
from langgraph.store.memory import InMemoryStore

store = InMemoryStore()  # 生产环境建议用 DB-backed Store

agent = create_agent(
    "claude-sonnet-4-6",
    tools=[],
    store=store,
)
```

**生产环境推荐**：使用 PostgresStore

```python
from langgraph.store.postgres import PostgresStore

DB_URI = "postgresql://postgres:postgres@localhost:5432/postgres?sslmode=disable"

with PostgresStore.from_conn_string(DB_URI) as store:
    store.setup()
    agent = create_agent(..., store=store)
```

### 2. 记忆存储结构

- 每条记忆是一个 **JSON 文档**
- 通过 **namespace**（类似文件夹，常包含 user_id、org_id 等）和 **key**（类似文件名）组织
- 支持按内容过滤 + 向量相似度搜索（需配置 embedding）

示例：

```python
namespace = (user_id, application_context)
store.put(namespace, "a-memory", {
    "rules": ["User likes short, direct language", ...],
    "my-key": "my-value"
})

item = store.get(namespace, "a-memory")
items = store.search(namespace, filter={"my-key": "my-value"}, query="language preferences")
```

### 3. 在工具中读取长期记忆

通过 `ToolRuntime` 访问 `runtime.store`：

```python
@tool
def get_user_info(runtime: ToolRuntime[Context]) -> str:
    """Look up user info."""
    user_id = runtime.context.user_id
    user_info = runtime.store.get(("users",), user_id)
    return str(user_info.value) if user_info else "Unknown user"
```

调用时传入 `context=Context(user_id="user_123")`。

### 4. 在工具中写入长期记忆

同样通过 `runtime.store.put()`：

```python
@tool
def save_user_info(user_info: UserInfo, runtime: ToolRuntime[Context]) -> str:
    """Save user info."""
    runtime.store.put(("users",), runtime.context.user_id, dict(user_info))
    return "Successfully saved user info."
```

### 5. 关键要点

| 对比项   | Short-term Memory  | Long-term Memory                   |
| -------- | ------------------ | ---------------------------------- |
| 作用域   | 单个 thread        | 跨 thread / 跨会话                 |
| 底层     | Checkpoint / State | LangGraph Store                    |
| 组织方式 | 消息历史           | namespace + key 的 JSON 文档       |
| 典型用途 | 当前对话上下文     | 用户偏好、历史洞察、规则、长期知识 |

- 工具是读写长期记忆的主要入口（通过 `runtime.store`）。
- 生产环境务必使用持久化 Store（如 PostgresStore），`InMemoryStore` 仅适合开发测试。
- 支持向量检索（配置 `IndexConfig` + embedding 函数）。
- 更深入的记忆类型（语义、情景、程序）和写入策略，可参考 [Memory 概念指南](https://docs.langchain.com/oss/python/concepts/memory#long-term-memory)。
