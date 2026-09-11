```python
from collections import Counter
import re
from collections import defaultdict
import json

class ChineseBPETokenizer:
    def __init__(self,vocab_size: int = 10000,special_tokens: list = ["<PAD>", "<UNK>","<BOS>","<EOS>"]):
        self.vocab_size = vocab_size
        self.special_tokens = special_tokens
        self.vocab = {}                 # token -> id
        self.inverse_vocab = {}         # id -> token
        self.merges = {}                # (p0,p1)->merged_str
        self.ranks = {}                 # (p0,p1)-> priority_idx
    
    def _get_stats(self,raw_vocab):
        """统计相邻字符对(pair)在字典中的频率"""
        pairs = defaultdict(int)
        for word, freq in raw_vocab.items():
            for i in range(len(word) - 1):
                pairs[word[i], word[i+1]] += freq
        return pairs
    
    def _merge_vocab(self, pair, raw_vocab):
        """合并词频字典中所有的目标字符对"""
        p0, p1 = pair
        target = p0 + p1
        v_out = {}
        for word, freq in raw_vocab.items():
            new_word = []
            i = 0
            while i < len(word):
                if i < len(word) - 1 and word[i] == p0 and word[i+1] == p1:
                    new_word.append(target)
                    i += 2
                else:
                    new_word.append(word[i])
                    i += 1
            v_out[tuple(new_word)] = freq
        return v_out

    def train(self, text):
        """训练分词器"""
        # 1. 预处理空格，使用 'Ġ' 代替空格，保留空格边界信息
        text = text.replace(' ', 'Ġ')
        
        # 2. 预分词（Pre-tokenization）：使用正则切分文本
        # 防止汉字和标点、英文等无意义地合并在一起
        pattern = re.compile(r'[\u4e00-\u9fff]+|[a-zA-Z0-9Ġ]+|[^\u4e00-\u9fffa-zA-Z0-9Ġ\s]')
        lines = text.split('\n')
        
        # 构建初始词频字典，键为单字符组成的元组，值为频次
        raw_vocab = defaultdict(int)
        for line in lines:
            if not line.strip():
                continue
            tokens = pattern.findall(line)
            for token in tokens:
                raw_vocab[tuple(token)] += 1
                
        # 3. 提取所有基础字符，构建初始词表
        base_chars = set()
        for word in raw_vocab:
            for char in word:
                base_chars.add(char)
        base_vocab = sorted(list(base_chars))
        
        # 写入特殊 Token 和基础单字
        self.vocab = {tok: idx for idx, tok in enumerate(self.special_tokens)}
        for char in base_vocab:
            if char not in self.vocab:
                self.vocab[char] = len(self.vocab)
                
        # 4. 循环合并高频相邻对
        num_merges = self.vocab_size - len(self.vocab)
        if num_merges <= 0:
            print(f"基础字符数 ({len(self.vocab)}) 已经大于等于目标词表大小 ({self.vocab_size})，无需合并。")
            self.inverse_vocab = {idx: tok for tok, idx in self.vocab.items()}
            return
            
        print(f"基础字符数: {len(self.vocab)}")
        print(f"开始执行合并，目标进行 {num_merges} 次合并...")
        
        for i in range(num_merges):
            pairs = self._get_stats(raw_vocab)
            if not pairs:
                break
            # 找到频次最高的相邻对
            best_pair = max(pairs, key=pairs.get)
            
            # 如果最高频次只有 1，说明合并意义不明显，提前终止
            if pairs[best_pair] < 2:
                print(f"合并在第 {i} 步停止（未找到频次大于 1 的相邻对）")
                break
                
            merged_token = best_pair[0] + best_pair[1]
            self.merges[best_pair] = merged_token
            self.ranks[best_pair] = i
            self.vocab[merged_token] = len(self.vocab)
            print(f"合并第 {i} 步: {best_pair} -> {merged_token} (频次: {pairs[best_pair]})")

            # 更新词频字典
            raw_vocab = self._merge_vocab(best_pair, raw_vocab)
            
            # 打印训练进度（每10%输出一次）
            if (i + 1) % max(1, num_merges // 10) == 0:
                print(f"进度: {((i + 1) / num_merges * 100):.1f}%，当前最高频字符对: {best_pair} -> {merged_token} (频次: {pairs[best_pair]})")
                
        self.inverse_vocab = {idx: tok for tok, idx in self.vocab.items()}
        print(f"训练完成，最终词表大小: {len(self.vocab)}")

    def _encode_token(self, token_tuple):
        """对单个片段（元组形式）应用训练好的合并规则"""
        word = list(token_tuple)
        while len(word) > 1:
            pairs = [(word[i], word[i+1]) for i in range(len(word) - 1)]
            # 找到当前能够合并，且在训练中最早被合并的字符对（优先级最高）
            valid_pairs = [p for p in pairs if p in self.ranks]
            if not valid_pairs:
                break
            best_pair = min(valid_pairs, key=lambda p: self.ranks[p])
            
            # 替换/合并该字符对
            p0, p1 = best_pair
            new_word = []
            i = 0
            while i < len(word):
                if i < len(word) - 1 and word[i] == p0 and word[i+1] == p1:
                    new_word.append(p0 + p1)
                    i += 2
                else:
                    new_word.append(word[i])
                    i += 1
            word = new_word
        return word

    def encode(self, text):
        """对文本进行 BPE 编码，输出 ID 列表"""
        text = text.replace(' ', 'Ġ')
        pattern = re.compile(r'[\u4e00-\u9fff]+|[a-zA-Z0-9Ġ]+|[^\u4e00-\u9fffa-zA-Z0-9Ġ\s]')
        tokens = pattern.findall(text)
        
        encoded_ids = []
        unk_id = self.vocab.get("<unk>", 1)
        
        for token in tokens:
            # 引入缓存机制：对于高频重复的词段，能显著降低计算开销

            merged_word = self._encode_token(tuple(token))
                
            for subtoken in merged_word:
                encoded_ids.append(self.vocab.get(subtoken, unk_id))
        return encoded_ids

    def decode(self, ids):
        """将 ID 列表解码还原回文本"""
        tokens = [self.inverse_vocab.get(idx, "<unk>") for idx in ids]
        decoded_text = "".join(tokens)
        return decoded_text.replace('Ġ', ' ')

    def save(self, filepath):
        """将分词器模型保存为单个 JSON 文件"""
        # 将 merges 按照优先级（ranks 升序）重新整理为二维列表
        # JSON 不支持元组作为字典的 Key，所以存储为：[["我", "们"], ["喜", "欢"]]
        ordered_merges = [list(pair) for pair, _ in sorted(self.ranks.items(), key=lambda x: x[1])]
        
        model_state = {
            "vocab_size": self.vocab_size,
            "special_tokens": self.special_tokens,
            "vocab": self.vocab,
            "merges": ordered_merges
        }
        
        with open(filepath, 'w', encoding='utf-8') as f:
            json.dump(model_state, f, ensure_ascii=False, indent=2)
        print(f"分词器模型已成功保存至: {filepath}")

    def load(self, filepath):
        """从 JSON 文件加载分词器模型"""
        with open(filepath, 'r', encoding='utf-8') as f:
            model_state = json.load(f)
            
        self.vocab_size = model_state["vocab_size"]
        self.special_tokens = model_state["special_tokens"]
        self.vocab = model_state["vocab"]
        
        # 从二维列表中恢复 merges、ranks 映射关系
        self.merges = {}
        self.ranks = {}
        for idx, (p0, p1) in enumerate(model_state["merges"]):
            self.merges[(p0, p1)] = p0 + p1
            self.ranks[(p0, p1)] = idx
            
        # 重新生成反向查询字典
        self.inverse_vocab = {idx: tok for tok, idx in self.vocab.items()}

        print(f"分词器模型加载成功，词表大小: {len(self.vocab)}")

if __name__ == "__main__":
    file_path = "./dataset/doupo_cleaned.txt"
    content = ""
    with open(file_path, "r", encoding="utf-8") as f:
        content = f.read()

    tokenizer = ChineseBPETokenizer(vocab_size=10000)
    tokenizer.train(content)
    tokenizer.save("./tokenizer_model.json")
```

tokenizer_test.py

```python
from tokenizer import ChineseBPETokenizer

tokenizer = ChineseBPETokenizer()
tokenizer.load("./tokenizer_model.json")
text = "眼前的菩提古树，已经不知道存在了多少岁月，不过有一点很肯定，从远古时，它便是存在。"
encoded_ids = tokenizer.encode(text)
encoded_ids.insert(0, tokenizer.vocab.get("<BOS>", 0))

print("len: ", len(encoded_ids))
print("原文: ", text)
print("编码: ", encoded_ids)

for encoded_id in encoded_ids:
    token = tokenizer.inverse_vocab.get(encoded_id, "<unk>")
    print(f"ID: {encoded_id} -> Token: {token}")
```

