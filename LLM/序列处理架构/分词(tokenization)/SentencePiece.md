**SentencePiece** 是由 Google 推出的一款开源、与语言无关的**子词分词与反分词工具包**（同时它也是一种分词架构）。许多现代大语言模型（如 LLaMA、T5、Mistral 等）都将其作为底层分词器。

与传统的 BPE 或 WordPiece 相比，SentencePiece 最大的创新在于它**彻底打破了对语言特定预处理（Pre-tokenization）的依赖**。

# 传统分词器的痛点与 SentencePiece 的解决方案

### 1. 空格与分词假设（Whitespace Assumption）

- **传统痛点**：大多数分词器（如基于空格切词的算法）默认语言是用空格来分隔单词的。这对于英语等日耳曼语系很管用，但面对中文、日文等没有空格切词习惯的语言，或者包含特殊符号和代码的文本时，就会束手无策，必须依赖外部工具（如分词库、正则表达式规则）。
- **SentencePiece 的解决方式**：它把输入文本视为纯粹的**原始字节/Unicode 字符流**，空格本身也被当作一个普通的可见字符（通常被显式替换为一个特殊的元符号，如 `_` 或 ``）来统一处理。这使得它能以完全相同的方式处理任何语言（英文、中文、韩文、多语言混合等）。

### 2. 可逆与无损还原（Lossless Detokenization）

- 传统分词器在还原文本（Detokenization）时往往会丢失空格格式（例如分词后很难完美恢复原句中多余的空格或标点间距）。
- SentencePiece 的分词和反分词是**完全可逆、无损**的。因为空格作为 `_` 被编码进了 Token 序列中，只需要把 Token 连起来并把 `_` 替换回空格，就能百分之百还原出原始文本。

#  SentencePiece 的核心特性

1. **支持多种底层算法**：

   SentencePiece 内部主要实现了两种经典的子词算法：

   - **BPE (Byte-Pair Encoding)**：基于频率的贪心合并。
   - **Unigram Language Model (一元语言模型)**：通过概率评估所有候选子词，逐步裁剪掉对整体语言模型似然贡献最小的子词（这也是很多大模型选用 SentencePiece 时常搭配的算法模式）。

2. **端到端训练**：

   不需要做任何人工规则定制或词性标注，直接丢入大段原始文本语料，就能训练出专属的词表和模型。

3. **子词正则化（Subword Regularization）与 BPE-Dropout**：

   在训练或微调阶段，SentencePiece 能够为同一个句子随机生成多种不同的子词切分方式（通过对 Unigram 采样或引入 BPE-Dropout）。这相当于对文本进行了**数据增强**，能显著提升大模型对拼写错误、噪声和生僻表达的鲁棒性。

# 与 BPE / WordPiece 的对比

| 项目     | 传统 BPE         | WordPiece (BERT) | **SentencePiece**          |
| -------- | ---------------- | ---------------- | -------------------------- |
| 空格处理 | 通常先按空格分词 | 先按空格分词     | **空格也是符号**（`▁`）    |
| 预分词   | 需要             | 需要             | **不需要**                 |
| 中文支持 | 一般             | 一般             | **非常好**                 |
| 主要算法 | BPE              | WordPiece        | BPE 或 **Unigram**         |
| 代表模型 | GPT-2、RoBERTa   | BERT             | LLaMA、T5、ChatGLM、ALBERT |
| 词表符号 | 普通子词         | 带 `##`          | 带 `▁` 前缀                |

# 实际例子

```python
from transformers import AutoTokenizer

# LLaMA、T5 等都使用 SentencePiece
tokenizer = AutoTokenizer.from_pretrained("google/mt5-small")   # 或 "meta-llama/Llama-2-7b-hf"

text = "你好，世界！Hello world."
tokens = tokenizer.tokenize(text)
print(tokens)

encoded = tokenizer(text, return_tensors="pt")
print(encoded)
```

output:

```
['▁', '你', '好', ',', '世界', '!', 'Hello', '▁world', '.']
{'input_ids': tensor([[   259,   4235,   3586,    261,   8333,    309, 141528,   4836,    260,
              1]]), 'attention_mask': tensor([[1, 1, 1, 1, 1, 1, 1, 1, 1, 1]])}
```