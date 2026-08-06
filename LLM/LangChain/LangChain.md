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

| 参数            | 类型            | 说明                                           |
| --------------- | --------------- | ---------------------------------------------- |
| **temperature** | `float`         | 控制输出随机性。值越小越确定，越大越有创造性。 |
| **max_tokens**  | `int`           | 限制输出最大 token 数。有效控制输出的长度。    |
| **timeout**     | `int` / `float` | 请求超时时间（秒）。                           |
| **max_retries** | `int`           | 失败重试次数（默认通常为 6）。                 |
| **api_key**     | `str`           | API 密钥（也可用环境变量）。                   |
| **base_url**    | `str`           | 自定义 API 端点。                              |
| **model**       | `str`           | 模型名称。                                     |

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

