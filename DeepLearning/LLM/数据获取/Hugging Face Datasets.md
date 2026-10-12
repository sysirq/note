主要包括两部分：

- datasets 库（Python 开源库）：一个轻量级、高效的数据集处理库。
- Hugging Face Hub 上的数据集仓库：目前托管了接近 100 万个公开数据集（截至 2026 年中数据），覆盖文本、图像、音频、视频、多模态等多种类型。

| 功能                      | 说明                                                         |
| ------------------------- | ------------------------------------------------------------ |
| **一行代码加载**          | `load_dataset("数据集名称")` 即可下载并加载数据集            |
| **多格式支持**            | CSV、JSON、JSONL、Parquet、Arrow、文本、图像、音频、视频、PDF、NIfTI 等 |
| **多模态支持**            | 文本、音频、图像、视频、3D 医疗数据等                        |
| **流式加载（Streaming）** | 不需要完整下载超大数据集，边读边用（支持超大语料）           |
| **高效处理**              | 基于 Apache Arrow，支持零拷贝、内存映射，处理超大数据集也不吃内存 |
| **数据预处理**            | `map()`、`filter()`、`shuffle()` 等操作非常方便，支持多进程加速 |
| **与主流框架无缝集成**    | PyTorch、TensorFlow、JAX、Pandas、Polars、NumPy 等           |

# 例子

```python
from datasets import load_dataset

# 加载经典问答数据集 SQuAD
dataset = load_dataset("rajpurkar/squad")

# 查看训练集第一条数据
print(dataset["train"][0])

# 流式加载超大数据集（不下载完整文件）
streaming_dataset = load_dataset("HuggingFaceFW/fineweb", streaming=True)
```

# 参考资料

https://huggingface.co/datasets

https://huggingface.co/docs/datasets/index