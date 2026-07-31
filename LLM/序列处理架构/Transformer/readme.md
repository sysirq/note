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
- V 表示Value，表达我的具体信息，（真正被加权聚合的信息）。

$$
Q=XW_Q
$$


$$
K=XW_K
$$


$$
V=XW_V
$$

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