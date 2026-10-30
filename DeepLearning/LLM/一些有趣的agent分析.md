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

### D-Mail

D-Mail 机制是一个极具极客浪漫色彩的设计，其灵感直接来源于经典科幻动漫《命运石之门》（Steins;Gate）中的“D-Mail（向过去发送邮件）”概念。

 在进行复杂的二进制逆向工程时，LLM 很容易犯错（例如：误把一个日志函数当作核心密码校验函数，然后围绕它深入分析了 15 步）。
   * 传统做法： 要么让 LLM 在错路上继续错下去，要么让用户手动重置对话清空所有记忆。
   * D-Mail 做法： 智能体自己意识到“方向全错”，它主动调用 send_dmail 工具，指定回到第 3 步的检查点，并留下遗言：“别去查 0x401000 了，那是日志函数，真正的校验函数在
     0x402340！”。系统会自动截断历史，把教训灌输给过去的自己，然后带着新知识重新上路。

```python
        try:
            result = await step(
                provider=provider,
                system=agent.system_prompt,
                messages=messages,
                tools=tools_specs if tools_specs else None,
                tool_dispatch=tool_registry.dispatch,
                on_part=_on_text_part,
                on_tool_call=_on_tool_call_part,
                on_tool_result=_on_tool_result_part,
                on_thinking=_on_thinking_part,
            )
        except BackToTheFuture as dmail:
            logger.info(
                "D-Mail received! Reverting to checkpoint %d", dmail.checkpoint_id
            )
            # 1. 触发回调通知 UI / 日志
            if on_dmail:
                on_dmail(dmail.checkpoint_id, dmail.message)
           
            # 2. 瞬间回滚上下文到过去的那一步（抹杀之后所有的错误尝试
            await context.revert_to(dmail.checkpoint_id)
            
            # 3. 将来自未来的信件注入系统提示中
            await context.append_system(
                f"[D-Mail from your future self]: {dmail.message}\n\n"
                "Use this knowledge to avoid repeating the same work. "
                "Continue with the task, applying what you now know."
            )
            continue # <--- 带着未来记忆，从那个时间点继续执行！
        except Exception as e:
            logger.error(
                "Agent %s: unrecoverable error at step %d: %s",
                agent.name,
                step_no,
                e,
                exc_info=True,
            )
            return TurnOutcome.ERROR
```

# redamon

地址：https://github.com/samugit83/redamon

基于LangGraph编写

状态节点：

```python
        builder.add_node("initialize", _initialize)
        builder.add_node("think", _think)
        builder.add_node("execute_tool", _execute_tool)
        builder.add_node("execute_plan", _execute_plan)
        builder.add_node("await_approval", _await_approval)
        builder.add_node("process_approval", _process_approval)
        builder.add_node("await_question", _await_question)
        builder.add_node("process_answer", _process_answer)
        builder.add_node("generate_response", _generate_response)
        builder.add_node("await_tool_confirmation", _await_tool_confirmation)
        builder.add_node("process_tool_confirmation", _process_tool_confirmation)
        builder.add_node("deploy_fireteam", _deploy_fireteam)
        builder.add_node("fireteam_collect", _fireteam_collect)
        builder.add_node("process_fireteam_confirmation", _process_fireteam_confirmation)
```

如何判断是否进入死胡同：

- 完全不看 LLM 的自述，只看系统真实的资产收集列表有没有长度增加等

如何从死胡同恢复：

- 系统强行剥夺大模型的工具调用权，强制触发独立 LLM 调用执行 Deep Think。为了防止大模型在深思时“换汤不换药”，代码引入了 Jaccard 相似度查重算法，将大模型新规划的优先级列表与上一版规划计算 Jaccard 相似度，如果新计划与老失败计划相似度 >= 0.6 (60%)，将此警告钉在 Prompt 头部，重新生成。



当 RedAmon 遇到死路时，代码执行链路是极其严密的：

- 1.  工具执行完毕 ➔ 物理数据无增量 (detect_state_growth = False)
- 2.  LLM 试图自夸 "我找到了新东西" ➔ 被 audit_productivity_claim 拦截，强制降为 "no_progress"
- 3. 停滞计数器累加 ➔ compute_productivity_score 飙升进入 Red/Critical
- 4. think_node 启动硬干预:
    - 1. 方案 A: 强制执行 Deep Think，用 Jaccard 算法查重，拒绝同义词改写
    - 2. 方案 B: 物理阻断当前命令，迫使模型调用 switch_skill 换赛道
    - 3. 方案 C: LATS（语言智能体树搜索，Language Agent Tree Search） 将当前节点标为 pruned，自动回退到父节点走兄弟路线。