# 基于RNN的序列到序列模型

序列到序列模型（Sequence-to-Sequence，Seq2Seq） 是一种用于处理：输入是一个序列，输出也是一个序列。eg：机器翻译（英文到中文）、文本摘要（一篇文章->摘要）

Seq2Seq 主要由两个RNN组成：

- Encoder 编码器：把输入序列压缩成一个上下文向量c（context vector）, 一般就是最后的隐藏状态。

$$
h_t = f(h_{t-1}, x_t)
$$

其中f通常是 LSTM 或 GRU。

$$
c = h_T
$$

- Decoder 解码器：以上下文向量 c 作为初始隐藏状态 s0。解码过程通常以特殊的起始符 `<SOS>`（Start of Sequence）开始，以结束符 `<EOS>`（End of Sequence）终止。在每个时间步 t′，Decoder 根据前一个时刻的输出 yt′−1 和当前隐藏状态 st′，通过 Softmax 层预测当前词 yt′ 的概率分布。

$$
s_t = f(s_{t-1}, y_{t-1}, c)
$$

$$
p(y_t \mid y_{<t}, x) = g(s_t, y_{t-1}, c)
$$

- 其中 g  通常是线性层 + Softmax。

Encoder 使用 RNN 阅读整个输入序列，把它压缩成一个隐藏状态；Decoder 使用这个隐藏状态逐步生成输出序列。


```
输入序列 x = (x₁, x₂, ..., x_T)
          ↓
     ┌─────────────┐
     │   Encoder   │  ← RNN / LSTM / GRU
     └─────────────┘
          ↓
     上下文向量 c
          ↓
     ┌─────────────┐
     │   Decoder   │  ← 另一个 RNN / LSTM / GRU
     └─────────────┘
          ↓
输出序列 y = (y₁, y₂, ..., y_T')
```