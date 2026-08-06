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