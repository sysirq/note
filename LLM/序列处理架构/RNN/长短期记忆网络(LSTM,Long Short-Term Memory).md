长短期记忆（LSTM）网络是一种特殊的循环神经网络（RNN），由 Sepp Hochreiter 和 Jürgen Schmidhuber 于 1997 年提出，专门用来解决传统 RNN 在处理长序列时的梯度消失/爆炸问题。

LSTM 通过引入一个可以长期保存信息的细胞状态（cell state）（长期记忆），以及一组精心设计的门控机制（gates），让网络能够选择性地记住或遗忘信息，从而在较长的时间跨度上保持有效的梯度流动。

- 遗忘门（Forget Gate）：决定从细胞状态中丢弃哪些信息。
  ![image-20260729113829331](images/image-20260729113829331.png)

- 输入门（Input Gate）: 决定哪些新信息要写入细胞状态，并生成候选值。
  ![image-20260729113945908](images/image-20260729113945908.png)
  候选新记忆：
  ![image-20260729114040868](images/image-20260729114040868.png)
  
- 输出门（Output Gate）: 决定当前时刻输出什么。
  ![image-20260729114300627](images/image-20260729114300627.png)


- 新记忆 = 旧记忆 × 保留比例 + 新知识 × 加入比例
  ![image-20260729114240748](images/image-20260729114240748.png)

- 隐藏状态
  ![image-20260729114638747](images/image-20260729114638747.png)

总结一下：

- LSTM 是一个“记忆管理器”
- 有长期记忆 (C_t)
- 有短期输出（隐藏状态） (h_t)
- 有三个门控制信息流


```
输入 x_t

    |
    v

计算遗忘门

f_t

    |
    v

删除旧记忆


计算输入门

i_t

    |
    v

加入新记忆


得到：

C_t


    |
    v

输出门

o_t


    |
    v

得到：

h_t

```

# 本质

![image-20260729115747643](images/image-20260729115747643.png)

它实际上就是：

```
过去信息
+
现在信息

↓

矩阵重新组合

↓

计算重要程度

↓

得到0~1的开关
```

# 代码

```python
import torch
import torch.nn as nn
import numpy as np
import matplotlib.pyplot as plt

# ====================== 1. 生成模拟的真实气温数据 ======================
# 模拟一年（365天）的日平均气温：有趋势 + 季节性 + 噪声
np.random.seed(42)
days = np.arange(365)
# 基础温度 + 季节波动（一年一个周期） + 小噪声
temps = 15 + 10 * np.sin(2 * np.pi * days / 365) + np.random.normal(0, 1.5, 365)

# 可视化生成的气温数据
plt.figure(figsize=(10, 4))
plt.plot(days, temps, label="真实气温")
plt.xlabel("天数")
plt.ylabel("气温 (°C)")
plt.title("模拟的真实气温数据")
plt.legend()
plt.show()

# ====================== 2. 构建时间序列数据集 ======================
def create_sequences(data, seq_length):
    """把一维时间序列变成 (输入序列, 目标值) 的形式"""
    xs, ys = [], []
    for i in range(len(data) - seq_length):
        x = data[i:i+seq_length]
        y = data[i+seq_length]
        xs.append(x)
        ys.append(y)
    return np.array(xs), np.array(ys)

seq_length = 14          # 用过去14天的气温预测第15天
X, y = create_sequences(temps, seq_length)

# 划分训练集和测试集（前80%训练，后20%测试）
train_size = int(len(X) * 0.8)
X_train, X_test = X[:train_size], X[train_size:]
y_train, y_test = y[:train_size], y[train_size:]

# 转成 PyTorch Tensor，并增加特征维度（batch, seq_len, features）
X_train = torch.FloatTensor(X_train).unsqueeze(-1)  # (N, 14, 1)
y_train = torch.FloatTensor(y_train).unsqueeze(-1)
X_test  = torch.FloatTensor(X_test).unsqueeze(-1)
y_test  = torch.FloatTensor(y_test).unsqueeze(-1)

print(f"训练集形状: {X_train.shape}, 测试集形状: {X_test.shape}")

# ====================== 3. 定义 RNN 模型 ======================
class TempLSTM(nn.Module):
    def __init__(self, input_size=1, hidden_size=64, num_layers=2, output_size=1):
        super().__init__()
        self.rnn = nn.LSTM(
            input_size=input_size,
            hidden_size=hidden_size,
            num_layers=num_layers,
            batch_first=True          # 输入格式为 (batch, seq, feature)
        )
        self.fc = nn.Linear(hidden_size, output_size)
    
    def forward(self, x):
        # x: (batch, seq_len, 1)
        out, _ = self.rnn(x)          # out: (batch, seq_len, hidden_size)
        out = out[:, -1, :]           # 只取最后一个时间步的输出
        out = self.fc(out)            # (batch, 1)
        return out

model = TempLSTM()
criterion = nn.MSELoss()
optimizer = torch.optim.Adam(model.parameters(), lr=0.001)

# ====================== 4. 训练 ======================
epochs = 2000
train_losses = []

for epoch in range(epochs):
    model.train()
    optimizer.zero_grad()
    
    pred = model(X_train)
    loss = criterion(pred, y_train)
    loss.backward()
    optimizer.step()
    
    train_losses.append(loss.item())
    
    if (epoch + 1) % 30 == 0:
        print(f"Epoch [{epoch+1}/{epochs}], Loss: {loss.item():.4f}")

# ====================== 5. 预测 & 评估 ======================
model.eval()
with torch.no_grad():
    pred_test = model(X_test)

# 计算测试集 MSE
test_loss = criterion(pred_test, y_test).item()
print(f"\n测试集 MSE: {test_loss:.4f}")

# ====================== 6. 可视化结果 ======================
plt.figure(figsize=(12, 5))

# 真实值 vs 预测值
plt.subplot(1, 2, 1)
plt.plot(y_test.numpy(), label="真实气温", linewidth=2)
plt.plot(pred_test.numpy(), label="LSTM预测", linestyle="--")
plt.title("测试集：真实气温 vs LSTM预测")
plt.xlabel("测试样本")
plt.ylabel("气温 (°C)")
plt.legend()
plt.grid(True)

# 训练损失曲线
plt.subplot(1, 2, 2)
plt.plot(train_losses)
plt.title("训练损失 (MSE)")
plt.xlabel("Epoch")
plt.ylabel("Loss")
plt.grid(True)

plt.tight_layout()
plt.show()
```

