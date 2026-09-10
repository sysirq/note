字节对编码（Byte Pair Encoding, BPE） 是一种数据压缩算法，后来被广泛用于自然语言处理中的子词分词（subword tokenization）。

核心思想：迭代地合并出现频率最高的字符对（或字节对），把常见的字符组合变成新的符号，从而把词切分成有意义的子词单元。



# 算法步骤（训练阶段）

- 初始化：把语料中所有单词拆成字符序列，并在词末尾加上特殊结束符 </w>（或用空格等标记）。 同时统计每个单词的出现频率。

- 统计字符对频率：统计相邻字符对的出现次数（按词频加权）。
- 合并最高频字符对：找到出现次数最多的字符对，把它合并成一个新符号，加入词汇表。

# 示例

假设语料（带频率）：

```
low     5
lower   2
newest  6
widest  3
```

初始字符序列：

```
l o w </w>          5
l o w e r </w>      2
n e w e s t </w>    6
w i d e s t </w>    3
```

- 第1轮：最高频字符对是 e s（出现 9 次）→ 合并为 es

- 第2轮：最高频是 es t（出现 9 次）→ 合并为 est
- 第3轮：最高频是 l o（出现 7 次）→ 合并为 lo

……持续合并，最终可以得到类似：

```
low</w>
lower</w>
newest</w>
widest</w>
```

以及子词：lo, w, er, new, est 等。

然后使用已学习的 BPE 分词 (tokenization)新文本。



# 代码

```python
from collections import defaultdict, Counter
import re

class BPE:
    def __init__(self, num_merges=10):
        self.num_merges = num_merges
        self.merges = []          # 记录合并规则（按顺序）
        self.vocab = set()        # 最终词汇表

    def get_stats(self, vocab):
        """统计相邻字符对的出现频率"""
        pairs = defaultdict(int)
        for word, freq in vocab.items():
            symbols = word.split()
            for i in range(len(symbols) - 1):
                pairs[symbols[i], symbols[i + 1]] += freq
        return pairs

    def merge_vocab(self, pair, vocab):
        """把指定的字符对合并成新符号"""
        new_vocab = {}
        bigram = ' '.join(pair)
        pattern = re.compile(r'(?<!\S)' + re.escape(bigram) + r'(?!\S)')
        
        for word in vocab:
            new_word = pattern.sub(''.join(pair), word)
            new_vocab[new_word] = vocab[word]
        return new_vocab

    def train(self, corpus):
        """
        训练 BPE
        corpus: list of strings，例如 ["low", "lower", "newest", "widest"]
        """
        # 1. 初始化：把每个词拆成字符，并加上结束符 </w>
        vocab = Counter()
        for word in corpus:
            # 拆成字符并用空格连接，末尾加 </w>
            tokenized = ' '.join(list(word)) + ' </w>'
            vocab[tokenized] += 1

        print("===== 初始词汇表 =====")
        for w, f in vocab.items():
            print(f"{w}: {f}")

        # 2. 迭代合并
        for i in range(self.num_merges):
            pairs = self.get_stats(vocab)
            if not pairs:
                break

            # 找出频率最高的字符对
            best_pair = max(pairs, key=pairs.get)
            print(f"\n第 {i+1} 次合并: {best_pair} (频率={pairs[best_pair]})")

            # 执行合并
            vocab = self.merge_vocab(best_pair, vocab)
            self.merges.append(best_pair)

            # 打印当前状态
            print("当前词汇表:")
            for w, f in sorted(vocab.items(), key=lambda x: -x[1]):
                print(f"  {w}: {f}")

        # 3. 构建最终词汇表
        self.vocab = set()
        for word in vocab:
            self.vocab.update(word.split())

        print("\n===== 训练完成 =====")
        print("合并规则（按顺序）:")
        for i, pair in enumerate(self.merges, 1):
            print(f"  {i}. {pair[0]} + {pair[1]} → {pair[0]}{pair[1]}")
        print(f"\n最终词汇表大小: {len(self.vocab)}")
        print("词汇表内容:", sorted(self.vocab))

    def encode(self, word):
        """使用训练好的规则对单个词进行编码"""
        # 初始化为字符 + </w>
        symbols = list(word) + ['</w>']
        
        # 按照训练时的合并顺序依次尝试合并
        for pair in self.merges:
            i = 0
            while i < len(symbols) - 1:
                if symbols[i] == pair[0] and symbols[i + 1] == pair[1]:
                    # 合并
                    symbols = symbols[:i] + [pair[0] + pair[1]] + symbols[i + 2:]
                else:
                    i += 1
        
        return symbols

# ==================== 使用示例 ====================
if __name__ == "__main__":
    # 训练语料
    corpus = [
        "low", "low", "low", "low", "low",      # 5次
        "lower", "lower",                       # 2次
        "newest", "newest", "newest", "newest", "newest", "newest",  # 6次
        "widest", "widest", "widest"            # 3次
    ]

    # 创建 BPE 实例，设置合并 10 次
    bpe = BPE(num_merges=10)
    bpe.train(corpus)

    # 测试编码
    print("\n===== 编码测试 =====")
    test_words = ["low", "lower", "newest", "widest", "newestest", "lowest"]
    for word in test_words:
        tokens = bpe.encode(word)
        print(f"{word:12} → {tokens}")
```

Output:

```
===== 初始词汇表 =====
l o w </w>: 5
l o w e r </w>: 2
n e w e s t </w>: 6
w i d e s t </w>: 3

第 1 次合并: ('e', 's') (频率=9)
当前词汇表:
  n e w es t </w>: 6
  l o w </w>: 5
  w i d es t </w>: 3
  l o w e r </w>: 2

第 2 次合并: ('es', 't') (频率=9)
当前词汇表:
  n e w est </w>: 6
  l o w </w>: 5
  w i d est </w>: 3
  l o w e r </w>: 2

第 3 次合并: ('est', '</w>') (频率=9)
当前词汇表:
  n e w est</w>: 6
  l o w </w>: 5
  w i d est</w>: 3
  l o w e r </w>: 2

第 4 次合并: ('l', 'o') (频率=7)
当前词汇表:
  n e w est</w>: 6
  lo w </w>: 5
  w i d est</w>: 3
  lo w e r </w>: 2

第 5 次合并: ('lo', 'w') (频率=7)
当前词汇表:
  n e w est</w>: 6
  low </w>: 5
  w i d est</w>: 3
  low e r </w>: 2

第 6 次合并: ('n', 'e') (频率=6)
当前词汇表:
  ne w est</w>: 6
  low </w>: 5
  w i d est</w>: 3
  low e r </w>: 2

第 7 次合并: ('ne', 'w') (频率=6)
当前词汇表:
  new est</w>: 6
  low </w>: 5
  w i d est</w>: 3
  low e r </w>: 2

第 8 次合并: ('new', 'est</w>') (频率=6)
当前词汇表:
  newest</w>: 6
  low </w>: 5
  w i d est</w>: 3
  low e r </w>: 2

第 9 次合并: ('low', '</w>') (频率=5)
当前词汇表:
  newest</w>: 6
  low</w>: 5
  w i d est</w>: 3
  low e r </w>: 2

第 10 次合并: ('w', 'i') (频率=3)
当前词汇表:
  newest</w>: 6
  low</w>: 5
  wi d est</w>: 3
  low e r </w>: 2

===== 训练完成 =====
合并规则（按顺序）:
  1. e + s → es
  2. es + t → est
  3. est + </w> → est</w>
  4. l + o → lo
  5. lo + w → low
  6. n + e → ne
  7. ne + w → new
  8. new + est</w> → newest</w>
  9. low + </w> → low</w>
  10. w + i → wi

最终词汇表大小: 9
词汇表内容: ['</w>', 'd', 'e', 'est</w>', 'low', 'low</w>', 'newest</w>', 'r', 'wi']

===== 编码测试 =====
low          → ['low</w>']
lower        → ['low', 'e', 'r', '</w>']
newest       → ['newest</w>']
widest       → ['wi', 'd', 'est</w>']
newestest    → ['new', 'est', 'est</w>']
lowest       → ['low', 'est</w>']
```

中文：

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

