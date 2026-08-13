循环神经网络 (neural network)（RNN），包括长短期记忆网络（LSTM）和门控循环单元（GRU），都逐步处理序列。每个隐藏状态都是根据输入和前一个隐藏状态计算得出。存在并行化受限、难以处理长距离依赖问题。

# 缩放点积注意力(Scaled Dot-Product Attention)

Transformer 架构使用注意力作为其核心机制，取代了传统的序列处理方法。注意力机制 (attention mechanism)不依赖于逐步传递的隐藏状态，而是让模型在处理特定部分时，能够直接衡量输入序列不同部分的权重 (weight)。此项操作的基本单元是缩放点积注意力。

$$
Attention(Q,K,V)
=
softmax
(
\frac{QK^T}{\sqrt{d_k}}
)
V
$$

Q、K、V 为同一个输入 X 经过三个不同的线性变换得到的三个新的表示。

- 其中X为序列经过分词器分词得到的一个个Token，然后Token在转化为嵌入向量的一个矩阵。如: 有4个token，每个token用5维向量表示

$$
X=
\begin{bmatrix}
x_1\\
x_2\\
x_3\\
x_4
\end{bmatrix}
$$


$$
X \in R^{4\times5}
$$

- Q 表示 Query，表达我要查询什么（每一个token想要关注的信息）。
- K 表示Key，表达我是什么标签（每一个token提供的标签）。
- V 表示Value，表达我的具体信息，（每一个token提供那些信息,真正被加权聚合的信息,谁给我什么、多少内容）。

$$
Q=XW_Q
$$


$$
K=XW_K
$$


$$
V=XW_V
$$

- 匹配度计算

$$
QK^T
$$

  表示：每一个 token 的 Query 和所有 token 的 Key 之间的匹配程度（相关性分数）。

  它产生的是一个注意力分数矩阵（Attention Score Matrix）。

- softmax

  $$
  softmax(\frac{QK^T}{\sqrt{d_k}})
  $$

  转化为概率

- 最后V

  $$
  Output=AttentionWeight \times V
  $$

  根据关注比例，把其他词的信息拿过来。eg: 0.05V我+0.10V喜欢+0.85V吃.



### 形象化表示：

- Q 和 K 算出了什么？

  它们算出了一个 **(n,n) 的注意力权重矩阵**（也就是那张“契合度百分比表”）。比如，它告诉你：“词A 对 词1 的注意力是 10%，对 词2 是 70%，对 词3 是 20%”。

- 光有百分比（权重）够吗？不够。

  这就像你在搜索引擎输入关键词（Q），引擎通过对比网页标题（K）后，给你返回了一堆比例：*“应该看网页1（占10%），网页2（占70%），网页3（占20%）”*。 但是，**光有比例，你还是不知道这些网页里写了什么内容啊！**

- V 登场了：

  V（Value）就是每个网页里真正的正文干货内容。
所以，必须让“权重（百分比）”去乘以 V（内容），才能把各个地方的有用信息按比例“抓”过来，揉成一份综合资料。


# 多头注意力(Multi-Head Attention)

多头注意力（Multi-Head Attention） 是 Transformer 对单头缩放点积注意力的扩展。它让模型同时从多个不同的表示子空间关注信息，而不是只用一个视角 (单头 Attention 只能学习一种信息关联方式，而 Multi-Head Attention 让模型拥有多个独立的 Q/K/V 投影空间，使不同 Head 自动学习不同类型的关系（语法、语义、指代、长距离依赖等），最后融合成更丰富的表示)。





输入矩阵的维度是 
$$
d_{\text{model}}
$$
，我们将其分为 h 个头（Head）

多头的本质是：把原来的 

$$
d_{\text{model}}
$$

维空间切成 h个更小的子空间，分别做注意力，再拼回来。



$$
MultiHead(Q,K,V)
=
Concat
(
softmax(
\frac{Q_1K_1^T}{\sqrt{d_k}}
)V_1,
...
,
softmax(
\frac{Q_hK_h^T}{\sqrt{d_k}}
)V_h
)
W_O
$$


$$
MultiHead(Q,K,V)
=
Concat(head_1,...,head_n)W_O
$$

# 位置编码

我们需要一种方法将每个token的位置信息融入模型中。这通过位置编码 (positional encoding)来实现。

最终输入嵌入 = token嵌入 + 位置编码

数学表示

$$
X = E + PE
$$

- E: 词嵌入向量（Embedding）
- PE:位置编码（Position Encoding）
- X: Transformer真正输入

### 正弦余弦位置编码（绝对位置编码）

这是原始 Transformer（Vaswani et al., 2017，《Attention Is All You Need》）中使用的位置编码方式。它是一种固定的、非学习的位置编码，通过正弦和余弦函数直接计算得到(不同维度使用不同频率,高频维度捕捉相邻位置的细微变化，低频维度捕捉长距离的位置关系，多个频率组合形成唯一的位置表示)。

$$
PE(pos,2i)=sin(\frac{pos}{10000^{\frac{2i}{d_{model}}}})
$$


$$
PE(pos,2i+1)=cos(\frac{pos}{10000^{\frac{2i}{d_{model}}}})
$$

- pos：当前token的位置

- i：embedding的第几个维度，取值范围为(0到 d_model/2 - 1 )

- d_model：Transformer隐藏层维度

公式中的分母使得不同维度的正弦/余弦波具有不同的波长。当 i 较小时（低维），分母小，频率高，波形变化快，能够区分相邻位置的微小差异。当 i 较大时（高维），分母大，频率低，波形变化慢，能够区分较远距离的宏观位置。

绝对位置编码的局限性：

- 把“位置”当成一个固定的编号，但语言中的位置关系往往是**相对的、动态的**。

- 长度外推（Length Extrapolation）能力差：当序列远超训练长度时，性能明显下降，模型对未见过的位置组合泛化不佳。
- 平移不敏感性缺失：句子整体平移（前面加几个词）后，所有 token 的绝对位置都变了，表示也随之改变。



# 编码器与解码器堆叠

Transformer 的编码器-解码器（Encoder-Decoder）架构是最初《Attention Is All You Need》论文中提出的经典形态，专门用于处理序列到序列（Seq2Seq）的任务，例如机器翻译、文本摘要、语音识别等。

- Encoder（编码器栈）：一次性吞入完整的源语言序列（如英文句子），将其层层加工，转化为一组高维的上下文语义特征表示。

- Decoder（解码器栈）：逐步生成目标语言序列（如法文翻译）。它不仅依赖自身已经生成的历史输出，还要通过特殊的机制去“借用”编码器输出的全局语义。


### Encoder-Decoder Attention 

这是连接编码器和解码器的桥梁

$$
Attention(Q_{decoder},K_{encoder},V_{encoder})
$$

在这里，来自解码器上一层的输出被用来构建 Query（查询向量），而编码器的最终输出则被用来构建 Key（键向量） 和 Value（值向量）。这使得解码器在生成每一个目标词时，都能回过头去精准检索源文本中最相关的部分。
