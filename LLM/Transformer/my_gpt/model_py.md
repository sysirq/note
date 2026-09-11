```python
import torch
from dataset import DoupoDataset
from torch.utils.data import DataLoader
from tokenizer import ChineseBPETokenizer

class RotaryEmbedding(torch.nn.Module):
    def __init__(self, dim, max_seq_len, base=10000):
        """
        Rotary Postion Embedding(RoPE)模块
        Args:
            dim (int): 旋转嵌入的维度,通常是 dim // n_head
            max_seq_len (int): 最大序列长度
            base (int, optional): 基数，默认为10000
        """
        super(RotaryEmbedding, self).__init__()
        self.dim = dim
        self.max_seq_len = max_seq_len
        self.base = base

        # 计算每个维度的旋转频率(inv_freq)
        # θ_i = base^(-2(i-1)/d)
        inv_freq = 1.0 / (base ** (torch.arange(0, dim, 2).float() / dim))
        self.register_buffer("inv_freq", inv_freq, persistent=False)

        # 预计算cos/sin缓存
        self._set_cos_sin_cache(max_seq_len, device="cpu")

    def _set_cos_sin_cache(self,seq_len,device):
        self.max_seq_len_cached = seq_len

        # 生成位置坐标 [0, 1, 2, ..., seq_len - 1]
        t = torch.arange(seq_len, device=device ,dtype=self.inv_freq.dtype)

        # 以外积计算所有位置在各个维度上的旋转角 (m * θ_i)
        # t 的形状: [seq_len], inv_freq 的形状: [dim / 2] -> freqs 形状: [seq_len, dim / 2]
        freqs = torch.outer(t, self.inv_freq)

        # 拼接频率以匹配完整的特征维度 [seq_len, dim]
        # 此处复制拼接是为了和后文 rotate_half() 的切片形式完美对齐
        emb = torch.cat((freqs, freqs), dim=-1)

        # 缓存cos和sin值，避免每次计算
        self.register_buffer("cos_cached", emb.cos(), persistent=False)
        self.register_buffer("sin_cached", emb.sin(), persistent=False)
        
    def forward(self, x ,seq_len = None):
        if seq_len is None:
            seq_len=x.shape[-2]
            
        if seq_len > self.max_seq_len_cached:
            self._set_cos_sin_cache(seq_len, device=x.device)

        return self.cos_cached[:seq_len, :].to(device=x.device, dtype=x.dtype), self.sin_cached[:seq_len, :].to(device=x.device, dtype=x.dtype)

def rotate_half(x):
    """
    旋转半维度的技巧 (Rotate Half)：
    将输入 x 在最后一个维度拆分为两半：[x1, x2] -> [-x2, x1]
    """
    x1 = x[..., : x.shape[-1] // 2]
    x2 = x[..., x.shape[-1] // 2 :]
    return torch.cat((-x2, x1), dim=-1)

def apply_rotary_pos_emb(q, k, cos, sin):
    """
    将旋转位置编码应用到查询和键张量上

    args:
        q,k 的形状为[batch_size,num_heads,seq_len,head_dim]
        cos,sin 的形状为[seq_len,head_dim]
    """
    seq_len = q.shape[-2]
    cos = cos[:seq_len].unsqueeze(0).unsqueeze(1) # [1, 1, seq_len, head_dim]
    sin = sin[:seq_len].unsqueeze(0).unsqueeze(1) # [1, 1, seq_len, head_dim]

    q_embed = (q * cos) + (rotate_half(q) * sin)
    k_embed = (k * cos) + (rotate_half(k) * sin)
    return q_embed, k_embed

class RMSNorm(torch.nn.Module):
    def __init__(self, dim, eps=1e-6):
        super(RMSNorm, self).__init__()
        self.dim = dim
        self.eps = eps
        self.weight = torch.nn.Parameter(torch.ones(dim))

    def _norm(self, x):
        # 计算均方根倒数，并与原输入相乘
        # x.pow(2).mean(-1, keepdim=True) 计算每个 token 特征向量的平方均值
        return x * torch.rsqrt(x.pow(2).mean(-1, keepdim=True) + self.eps)

    def forward(self, x):
        output = self._norm(x.float()).type_as(x)
        return self.weight * output

class Attention(torch.nn.Module):
    def __init__(self, max_seq_len, d_model, num_heads, dropout=0.1):
        super(Attention, self).__init__()

        self.d_model = d_model
        self.num_heads = num_heads
        self.head_dim = d_model // num_heads

        self.wq = torch.nn.Linear(d_model, d_model)
        self.wk = torch.nn.Linear(d_model, d_model)
        self.wv = torch.nn.Linear(d_model, d_model)
        self.out_proj = torch.nn.Linear(d_model, d_model)
        self.dropout = torch.nn.Dropout(dropout)

        # 屏蔽矩阵，用于在自注意力中屏蔽某些位置
        
        self.register_buffer("mask", torch.tril(torch.ones(max_seq_len, max_seq_len)).unsqueeze(0).unsqueeze(0),persistent=False) # [1, 1, max_seq_len, max_seq_len]
        

    def forward(self, x, cos=None, sin=None):
        batch_size, seq_len, _ = x.size()

        q = self.wq(x).view(batch_size, seq_len, self.num_heads, self.head_dim).permute(0, 2, 1, 3)
        k = self.wk(x).view(batch_size, seq_len, self.num_heads, self.head_dim).permute(0, 2, 1, 3)
        v = self.wv(x).view(batch_size, seq_len, self.num_heads, self.head_dim).permute(0, 2, 1, 3)

        if cos is not None and sin is not None:
            q, k = apply_rotary_pos_emb(q, k, cos, sin)

        # 计算注意力分数
        attn_scores = torch.matmul(q, k.transpose(-2, -1)) / (self.head_dim ** 0.5)

        # 应用因果掩码
        attn_scores = attn_scores.masked_fill(self.mask[:, :, :seq_len, :seq_len] == 0, float('-inf'))

        attn_probs = torch.nn.functional.softmax(attn_scores, dim=-1)
        attn_probs = self.dropout(attn_probs)

        context = torch.matmul(attn_probs, v)
        context = context.permute(0, 2, 1, 3).contiguous()
        context = context.view(batch_size, seq_len, self.d_model)
        out = self.out_proj(context)

        return out

class MLP(torch.nn.Module):
    def __init__(self,d_model, hidden_dim= None,multiple_of=256):
        """
        Args:
            d_model: 模型输入/输出层维度
            hidden_dim: 中间层展开维度。
            multiple_of: 内存对齐的基数
        """
        super().__init__()
        # 如果未指定 hidden_dim，通常按照 LLaMA 的论文公式计算
        # hidden_dim = 8/3 * d_model，然后向上取整到 multiple_of 的倍数
        if hidden_dim is None:
            hidden_dim = int(2 * d_model * 4 / 3) # 即 8/3 * d_model
            hidden_dim = multiple_of * ((hidden_dim + multiple_of - 1) // multiple_of)

        # SwiGLU 需要三个独立的投影矩阵，且统一去掉了 bias
        self.gate_proj = torch.nn.Linear(d_model, hidden_dim, bias=False) # W_gate
        self.up_proj = torch.nn.Linear(d_model, hidden_dim, bias=False)   # W_up
        self.down_proj = torch.nn.Linear(hidden_dim, d_model, bias=False) # W_down
    def forward(self, x):
        # 1. 门控路径: F.silu(self.gate_proj(x))
        # 2. 线性路径: self.up_proj(x)
        # 3. 逐元素相乘后降维投影
        return self.down_proj(torch.nn.functional.silu(self.gate_proj(x)) * self.up_proj(x))

class DecoderLayer(torch.nn.Module):
    def __init__(self, max_seq_len, layer_id, d_model, nhead, hidden_dim, dropout=0.1):
        super().__init__()
        self.layer_id = layer_id
        self.self_attn = Attention(max_seq_len,d_model, nhead, dropout=dropout)
        self.mlp = MLP(d_model, hidden_dim)
        self.norm1 = RMSNorm(d_model)
        self.norm2 = RMSNorm(d_model)
        self.dropout = torch.nn.Dropout(dropout)
    def forward(self, x, cos=None, sin=None):
        # 自注意力子层
        attn_out = self.self_attn(self.norm1(x), cos=cos, sin=sin)
        x = x + self.dropout(attn_out)

        # MLP 子层
        mlp_out = self.mlp(self.norm2(x))
        x = x + self.dropout(mlp_out)

        return x

class TransformerModel(torch.nn.Module):
    def __init__(self,seq_len,max_seq_len, vocab_size, d_model, nhead , num_layers, hidden_dim=2048, dropout=0.1):
        super(TransformerModel, self).__init__()
        self.seq_len = seq_len
        self.max_seq_len = max_seq_len

        self.embedding = torch.nn.Embedding(vocab_size, d_model)
        self.out = torch.nn.Linear(d_model, vocab_size)
        self.dropout = torch.nn.Dropout(dropout)
        self.layers = torch.nn.ModuleList([
            DecoderLayer(max_seq_len=max_seq_len, layer_id=i, d_model=d_model, nhead=nhead, hidden_dim=hidden_dim, dropout=dropout)
            for i in range(num_layers)
        ])
        self.norm = RMSNorm(d_model)
        self.rope = RotaryEmbedding(d_model // nhead, max_seq_len)

    def forward(self, tokens):
        batch_size,seq_len = tokens.shape
        # 通过嵌入层和dropout层
        h = self.embedding(tokens)
        h = self.dropout(h)

        cos, sin = self.rope(h, seq_len)

        for layer in self.layers:
            h = layer(h,cos=cos, sin=sin)

        h = self.norm(h)

        logits = self.out(h)
        return logits

def train_model(batch_size,d_model,d_hidden,num_heads,num_layers,seq_len,max_seq_len): 
    tokenizer = ChineseBPETokenizer()
    tokenizer.load("tokenizer_model.json")
    dataset = DoupoDataset("./dataset/doupo_cleaned.txt", tokenizer, max_length=seq_len)
    dataloader = DataLoader(dataset, batch_size=batch_size, shuffle=True)

    model = TransformerModel(seq_len, max_seq_len, tokenizer.vocab_size, d_model, num_heads, num_layers,hidden_dim=d_hidden, dropout=0.1)

    param_dict = {pn: p for pn, p in model.named_parameters() if p.requires_grad}
    decay_params = [p for n, p in param_dict.items() if p.dim() >= 2] # 矩阵权重需要衰减
    nodecay_params = [p for n, p in param_dict.items() if p.dim() < 2] # 一维的Norm权重和Bias不衰减
    optim_groups = [
        {'params': decay_params, 'weight_decay': 0.1},
        {'params': nodecay_params, 'weight_decay': 0.0}
    ]
    optimizer = torch.optim.AdamW(optim_groups, lr=3e-4)

    print("total_params:", sum(p.numel() for p in model.parameters()))

    loss_fn = torch.nn.CrossEntropyLoss(reduction="none")

    save_interval = 1000
    global_step = 0

    for epoch in range(10):
        model.train()
        total_loss = 0
        for tokens, target, loss_mask in dataloader:

            optimizer.zero_grad()
            logits = model(tokens)
            loss = loss_fn(logits.view(-1, tokenizer.vocab_size), target.view(-1))
            loss = loss * loss_mask.view(-1)
            loss = loss.sum() / loss_mask.sum()
            loss.backward()
            optimizer.step()

            total_loss += loss.item()
            global_step += 1
            print(f"Step {global_step}, Loss: {loss.item()}")
            if global_step % save_interval == 0:
                checkpoint = {
                    "epoch": epoch,
                    "global_step": global_step,
                    "model":model.state_dict(),
                    "model_config": {
                        "seq_len": seq_len,
                        "vocab_size": tokenizer.vocab_size,
                        "d_model": d_model,
                        "d_hidden": d_hidden,
                        "nhead": num_heads,
                        "num_layers": num_layers,
                        "max_seq_len": max_seq_len
                    },
                    "optimizer": optimizer.state_dict(),
                    "loss": loss.item()
                }
                print(f"Saving model at step {global_step}")
                torch.save(checkpoint, f"checkpoint/model_checkpoint.pt")
        print(f"Epoch {epoch+1}, Loss: {total_loss/len(dataloader)}")

if __name__ == "__main__":
    batch_size = 32
    d_model = 512
    d_hidden = 2048
    num_heads = 8
    num_layers = 6
    seq_len = 512
    max_seq_len = 2048

    train_model(batch_size=batch_size,d_model=d_model,d_hidden=d_hidden,num_heads=num_heads,num_layers=num_layers,seq_len=seq_len,max_seq_len=max_seq_len)
```

model_test.py

```python
from model import TransformerModel
from tokenizer import ChineseBPETokenizer
import torch


if __name__ == "__main__":
    # 加载checkpoint
    checkpoint = torch.load("./checkpoint/model_checkpoint.pt")
    model = TransformerModel(
        seq_len=checkpoint["model_config"]["seq_len"],
        max_seq_len=checkpoint["model_config"]["max_seq_len"],
        vocab_size=checkpoint["model_config"]["vocab_size"],
        d_model=checkpoint["model_config"]["d_model"],
        nhead=checkpoint["model_config"]["nhead"],
        num_layers=checkpoint["model_config"]["num_layers"],
        hidden_dim=checkpoint["model_config"]["d_hidden"],
        dropout=0.1
    )
    model.load_state_dict(checkpoint["model"])
    model.eval()

    # 加载分词器
    tokenizer = ChineseBPETokenizer()
    tokenizer.load("./tokenizer_model.json")
    eos_token = tokenizer.vocab.get("<EOS>")

    # 测试模型
    test_sentence = "我要干翻这世界"
    test_tokens = tokenizer.encode(test_sentence)

    print("Test sentence:", test_sentence)
    print("Output sentence:", tokenizer.decode(test_tokens),end="",flush=True)

    output_tokens = test_tokens
    while len(output_tokens) < checkpoint["model_config"]["max_seq_len"]:
        with torch.no_grad():
            output = model(torch.tensor(output_tokens).unsqueeze(0))
            next_token = output[:, -1, :].argmax(dim=-1)

            if eos_token in next_token.tolist():
                            break

            output_tokens = output_tokens + next_token.tolist()
            print(tokenizer.decode(next_token.tolist()), end="", flush=True)

    print("")
```

Output:

```
分词器模型加载成功，词表大小: 10000
Test sentence: 我要干翻这世界
Output sentence: 我要干翻这世界上，恐怕少不了什么”
```



