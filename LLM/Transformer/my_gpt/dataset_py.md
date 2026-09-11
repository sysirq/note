```python
from torch.utils.data import Dataset, DataLoader
from tokenizer import ChineseBPETokenizer
import torch

class DoupoDataset(Dataset):
    def __init__(
            self,
            filepath: str,
            tokenizer: ChineseBPETokenizer,
            max_length=512,
            stride=None
    ):
        self.tokenizer = tokenizer
        self.max_length = max_length

        eos_id = tokenizer.vocab.get("<EOS>")

        # 默认重叠一半
        if stride is None:
            stride = max_length//2

        self.stride = stride

        # =========================
        # 1. 读取完整小说
        # =========================

        with open(
            filepath,
            "r",
            encoding="utf-8"
        ) as f:

            content = f.read()



        # =========================
        # 2. 整本小说tokenize
        # =========================
        tokens = []
        lines = content.split("\n")
        for line in lines:
            if line.strip() == "":
                continue
            tokens.extend(tokenizer.encode(line))
            if eos_id is not None:
                tokens.append(eos_id)

        self.tokens = tokens

        # =========================
        # 3. 计算样本数量
        # =========================

        self.num_samples = (
            len(self.tokens)
            - max_length
            - 1
        ) // stride + 1

        print(
            f"总token数量: {len(self.tokens)}"
        )

        print(
            f"训练样本数量: {self.num_samples}"
        )


    def __len__(self):
        return self.num_samples

    def __getitem__(self, idx):
        pad_id = self.tokenizer.vocab["<PAD>"]
        # 当前窗口开始位置
        start = idx * self.stride

        chunk = self.tokens[
            start:
            start+self.max_length+1
        ]

        # 理论上不会发生
        if len(chunk) < self.max_length+1:
            chunk += [
                pad_id
            ] * (
                self.max_length + 1 - len(chunk)
            )

        # GPT训练格式
        X = chunk[:-1]
        Y = chunk[1:]
        mask = [
            1 if token != pad_id else 0
            for token in Y
        ]

        return (
            torch.tensor(
                X,
                dtype=torch.long
            ),

            torch.tensor(
                Y,
                dtype=torch.long
            ),
            torch.tensor(
                mask,
                dtype=torch.long
            )
        )

if __name__ == "__main__":
    tokenizer = ChineseBPETokenizer()
    tokenizer.load("tokenizer_model.json")
    dataset = DoupoDataset("./dataset/doupo_cleaned.txt", tokenizer, max_length=512)
    dataloader = DataLoader(dataset, batch_size=1, shuffle=True)
    for X, Y, mask in dataloader:
        for i in range(X.shape[-1]):
            x = X[0, i]
            y = Y[0, i]
            m = mask[0, i]
    
            print(f"Step {i}: x={x} {tokenizer.decode([x.item()])}\t, y={y} {tokenizer.decode([y.item()])}\t, \tmask={m}")
        break
```

