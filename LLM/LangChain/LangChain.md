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

# Event Streaming

