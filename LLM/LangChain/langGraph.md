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

