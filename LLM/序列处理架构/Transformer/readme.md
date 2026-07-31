循环神经网络 (neural network)（RNN），包括长短期记忆网络（LSTM）和门控循环单元（GRU），都逐步处理序列。每个隐藏状态都是根据输入和前一个隐藏状态计算得出。存在并行化受限、难以处理长距离依赖问题。

# 缩放点积注意力(Scaled Dot-Product Attention).md

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