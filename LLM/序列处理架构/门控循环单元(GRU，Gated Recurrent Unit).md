门控循环单元（GRU，Gated Recurrent Unit）是由 Cho 等人在 2014 年提出的一种优秀的循环神经网络（RNN）变体。

可以将 GRU 看作是 LSTM 的“精简版”。它吸取了 LSTM 核心的门控思想，但通过精简结构减少了参数量，从而在保持优秀长期记忆能力的同时，具备了更快的训练速度和更高的计算效率。

- 更新门：决定保留多少过去信息

$$
z_t=\sigma(W_z[h_{t-1},x_t]+b_z)
$$

- 重制门：忘掉多少过去信息

$$
r_t=\sigma(W_r[h_{t-1},x_t]+b_r)
$$

- 候选隐藏状态

$$
\tilde{h}_t=
tanh(W_h[r_t*h_{t-1},x_t]+b_h)
$$

- 最终隐藏状态

$$
h_t=(1-z_t)*h_{t-1}+z_t*\tilde{h}_t
$$

用一个由神经网络学习出来的门 Zt，动态决定过去信息和当前信息的比例；再用重置门 rt决定过去信息是否参与新记忆生成。

```
             x_t
              |
              |
        +-----+------+
        |            |
        ↓            ↓

     更新门 z      重置门 r

        |            |
        |            |
        ↓            ↓

     保留比例     删除比例


              |
              ↓

        候选记忆 h~

              |
              |
              ↓

 h(t-1) ---------> h(t)

       z 控制混合
```

# 代码

天气预测

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
class TempGRU(nn.Module):
    def __init__(self, input_size=1, hidden_size=64, num_layers=2, output_size=1):
        super().__init__()
        self.rnn = nn.GRU(
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

model = TempGRU()
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
plt.plot(pred_test.numpy(), label="GRU预测", linestyle="--")
plt.title("测试集：真实气温 vs GRU预测")
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