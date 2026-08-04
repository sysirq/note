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

