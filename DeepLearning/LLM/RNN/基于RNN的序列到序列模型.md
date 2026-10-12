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

# 例子代码

数字反转

```python
import torch
import torch.nn as nn
import torch.optim as optim
import random
import numpy as np

# ===================== 1. 特殊标记与词表 =====================
PAD = 0
SOS = 1
EOS = 2
# 数字 0~9 对应 token 3~12
NUM_OFFSET = 3
VOCAB_SIZE = 13          # 0=PAD, 1=SOS, 2=EOS, 3~12=数字0~9

device = torch.device('cuda' if torch.cuda.is_available() else 'cpu')

# ===================== 2. 数据生成 =====================
def generate_batch(batch_size=32, min_len=3, max_len=8):
    """生成一批「数字序列 → 反序列」数据"""
    src_batch, trg_batch = [], []
    for _ in range(batch_size):
        length = random.randint(min_len, max_len)
        # 随机生成数字序列（0~9）
        nums = [random.randint(0, 9) for _ in range(length)]
        # 源序列：数字token + EOS
        src = [n + NUM_OFFSET for n in nums] + [EOS]
        # 目标序列：SOS + 反序数字 + EOS
        trg = [SOS] + [n + NUM_OFFSET for n in reversed(nums)] + [EOS]
        src_batch.append(src)
        trg_batch.append(trg)

    # 填充到相同长度
    max_src = max(len(s) for s in src_batch)
    max_trg = max(len(t) for t in trg_batch)

    src_padded = [s + [PAD] * (max_src - len(s)) for s in src_batch]
    trg_padded = [t + [PAD] * (max_trg - len(t)) for t in trg_batch]

    return (torch.tensor(src_padded, dtype=torch.long).to(device),
            torch.tensor(trg_padded, dtype=torch.long).to(device))


# ===================== 3. 模型定义 =====================
class Encoder(nn.Module):
    def __init__(self, vocab_size, emb_dim, hid_dim, n_layers=1):
        super().__init__()
        self.embedding = nn.Embedding(vocab_size, emb_dim, padding_idx=PAD)
        self.rnn = nn.LSTM(emb_dim, hid_dim, n_layers, batch_first=True)

    def forward(self, src):
        embedded = self.embedding(src)
        outputs, (hidden, cell) = self.rnn(embedded)
        return hidden, cell


class Decoder(nn.Module):
    def __init__(self, vocab_size, emb_dim, hid_dim, n_layers=1):
        super().__init__()
        self.embedding = nn.Embedding(vocab_size, emb_dim, padding_idx=PAD)
        # 输入 = 词嵌入 + 上下文向量
        self.rnn = nn.LSTM(emb_dim + hid_dim, hid_dim, n_layers, batch_first=True)
        self.fc_out = nn.Linear(hid_dim, vocab_size)

    def forward(self, input, hidden, cell, context):
        # input: [batch]
        input = input.unsqueeze(1)                     # [batch, 1]
        embedded = self.embedding(input)               # [batch, 1, emb_dim]

        # 把上下文拼接到输入上
        context = context[-1].unsqueeze(1)             # [batch, 1, hid_dim]
        rnn_input = torch.cat((embedded, context), dim=2)

        # ========== 这里调用 RNN ==========
        output, (hidden, cell) = self.rnn(rnn_input, (hidden, cell))

        prediction = self.fc_out(output.squeeze(1))    # [batch, vocab_size]
        return prediction, hidden, cell


class Seq2Seq(nn.Module):
    def __init__(self, encoder, decoder):
        super().__init__()
        self.encoder = encoder
        self.decoder = decoder

    def forward(self, src, trg, teacher_forcing_ratio=0.5):
        batch_size, trg_len = trg.shape
        outputs = torch.zeros(batch_size, trg_len, VOCAB_SIZE).to(device)

        hidden, cell = self.encoder(src)
        input = trg[:, 0]          # 第一个输入是 <SOS>

        for t in range(1, trg_len):
            prediction, hidden, cell = self.decoder(input, hidden, cell, context=hidden)
            outputs[:, t] = prediction

            teacher_force = random.random() < teacher_forcing_ratio
            top1 = prediction.argmax(1)
            input = trg[:, t] if teacher_force else top1

        return outputs


# ===================== 4. 训练 =====================
EMB_DIM = 64
HID_DIM = 128
N_LAYERS = 1

encoder = Encoder(VOCAB_SIZE, EMB_DIM, HID_DIM, N_LAYERS).to(device)
decoder = Decoder(VOCAB_SIZE, EMB_DIM, HID_DIM, N_LAYERS).to(device)
model = Seq2Seq(encoder, decoder).to(device)

optimizer = optim.Adam(model.parameters(), lr=0.001)
criterion = nn.CrossEntropyLoss(ignore_index=PAD)

print("开始训练...")
for epoch in range(1, 31):
    model.train()
    total_loss = 0
    for _ in range(50):          # 每个epoch跑50个batch
        src, trg = generate_batch(batch_size=64)
        optimizer.zero_grad()
        output = model(src, trg, teacher_forcing_ratio=0.5)

        # 计算损失（忽略PAD，且不计算第0个位置的SOS）
        output_dim = output.shape[-1]
        output = output[:, 1:].reshape(-1, output_dim)
        trg = trg[:, 1:].reshape(-1)
        loss = criterion(output, trg)
        loss.backward()
        optimizer.step()
        total_loss += loss.item()

    if epoch % 5 == 0:
        print(f"Epoch {epoch:2d} | Loss: {total_loss/50:.4f}")


# ===================== 5. 推理函数 =====================
def reverse_sequence(model, nums, max_len=15):
    """输入一个数字列表，返回模型预测的反序列"""
    model.eval()
    with torch.no_grad():
        # 构造源序列
        src = [n + NUM_OFFSET for n in nums] + [EOS]
        src = torch.tensor(src).unsqueeze(0).to(device)   # [1, src_len]

        hidden, cell = model.encoder(src)
        input_token = torch.tensor([SOS]).to(device)

        result = []
        for _ in range(max_len):
            prediction, hidden, cell = model.decoder(input_token, hidden, cell, context=hidden)
            pred_token = prediction.argmax(1).item()

            if pred_token == EOS:
                break
            if pred_token >= NUM_OFFSET:          # 只收集数字
                result.append(pred_token - NUM_OFFSET)
            input_token = torch.tensor([pred_token]).to(device)

        return result


# ===================== 6. 测试几个例子 =====================
print("\n===== 测试结果 =====")
test_cases = [
    [1, 2, 3, 4],
    [9, 8, 7],
    [0, 5, 2, 8, 1],
    [3, 3, 3, 3],
    [6],
    [2, 3, 4, 2, 6, 2],
]

for seq in test_cases:
    pred = reverse_sequence(model, seq)
    print(f"输入: {seq}  →  预测: {pred}  →  正确: {list(reversed(seq))}")
```

Output:

```
开始训练...
Epoch  5 | Loss: 0.8839
Epoch 10 | Loss: 0.3063
Epoch 15 | Loss: 0.1237
Epoch 20 | Loss: 0.0821
Epoch 25 | Loss: 0.0503
Epoch 30 | Loss: 0.0484

===== 测试结果 =====
输入: [1, 2, 3, 4]  →  预测: [4, 3, 2, 1, 1, 2]  →  正确: [4, 3, 2, 1]
输入: [9, 8, 7]  →  预测: [7, 8, 9, 7, 8]  →  正确: [7, 8, 9]
输入: [0, 5, 2, 8, 1]  →  预测: [1, 8, 2, 5, 0, 0]  →  正确: [1, 8, 2, 5, 0]
输入: [3, 3, 3, 3]  →  预测: [3, 3, 3, 7, 3, 3]  →  正确: [3, 3, 3, 3]
输入: [6]  →  预测: [6, 6, 1, 9]  →  正确: [6]
输入: [2, 3, 4, 2, 6, 2]  →  预测: [2, 6, 2, 4, 3, 2, 3]  →  正确: [2, 6, 2, 4, 3, 2]

```

