# reagent

地址：https://github.com/criticic/reagent

### 多个子agent

- static ： 主要进行静态分析 与 反汇编
- dynamic ： 动态调试，对提出的假设进行验证

### 共享知识库

BinaryModel 是整个系统的共享知识库（shared knowledge base）。它是所有 agent（orchestrator + subagent）之间交换分析成果的中央存储，把逆向分析的知识组织成三个递进层级，

1. Observation（客观观测值 —— 证据链的底座）
   * 本质：直接来自工具执行的原始回包，不作任何主观演绎。
   * 典型数据形态：
       * type="strings": 在二进制中提取到一段硬编码文本 "Invalid Password!"。
       * type="disassembly": 地址 0x401200 处的汇编指令是 cmp eax, 0x1 后跟 jne 0x401250。
       * type="trace": 在 GDB 中触发断点时，RAX = 0xdeadbeef。
   * 设计价值：它是防止 Agent 凭空编造事实的物理锚点。每个推测都必须能指向具体的 evidence: list[Observation.id]。

2. Hypothesis（假说 —— 探索行动的发动机）
   * 本质：Agent 基于现有观测提出的待检验理论。
   * 生命周期状态机（Status Lifecycle）：
   $$
   \text{proposed（提出）}
       \xrightarrow{\text{派发验证}}
       \text{testing（验证中）}
       \xrightarrow{\text{实测结果}}
       \begin{cases}
       \text{confirmed（证实，置信度 } 1.0\text{）} \
       \text{rejected（证伪，置信度 } 0.0\text{，记录原因）}
       \end{cases}
   $$
   * 关键属性解读：
       * confidence（置信度）：0.0 到 1.0，反映当前静态线索的强弱。
       * reject_reason：如果假设被证伪（如原以为是校验逻辑，实测发现只是个无用日志打印），记录失败原因，彻底杜绝 Agent 重蹈覆辙（防死循环）。
   * 设计价值：它把模糊的目标变成了具体可检验的任务单。Orchestrator 扫描所有 status="proposed" 的假设，就能明确下一步该派发谁去干什么。

3. Finding（最终发现 —— 交付给用户的真理）
   * 本质：经过证据闭环检验的真理，是系统的最终资产。
   * 产生机制：
       * 主要通过 promote_hypothesis(hypothesis_id, agent="dynamic") 晋升。
       * 将原 Hypothesis 的状态置为 confirmed，并将原始证据链（evidence）一并打包归档。
   * 关键属性解读：
       * verified_by：明确标注是哪个子 Agent（如 dynamic）通过什么手段完成了闭环。
   * 设计价值：最终生成的漏洞报告或逆向答案只信任 Finding，确保给人类用户的报告零幻觉、有实据。

Observation（客观观测）、Hypothesis（假设推测） 与 Finding（实证结论） 构成了整个系统认知状态机（Cognitive State Machine）的三大核心基石。

它们模拟了科学研究与人类资深安全专家的思维逻辑：“看客观事实” → “提科学假说” → “用实验验证” → “定事实结论”。