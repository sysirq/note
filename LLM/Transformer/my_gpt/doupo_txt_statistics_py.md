```python
"""
统计斗破苍穹小说txt文件的相关信息
需要统计以下信息：
1. 总字符数
2. 每行最大字符数(需要知道在哪一行)
3. 每行最小字符数(需要知道在哪一行)
4. 平均每行字符数
5. 总行数
6. 字符种类个数及其出现次数(包括空格和换行符以及各种符号，包括中文标点等，所有可见和不可见字符，从大到小排序)
"""

def statistics(file_path):
    with open(file_path, "r", encoding="utf-8") as f:
        lines = f.readlines()
    total_chars = sum(len(line) for line in lines)
    max_chars = max(len(line) for line in lines)
    min_chars = min(len(line) for line in lines)
    max_line_index = next(i for i, line in enumerate(lines) if len(line) == max_chars)
    min_line_index = next(i for i, line in enumerate(lines) if len(line) == min_chars)
    avg_chars = total_chars / len(lines) if lines else 0
    total_lines = len(lines)
    char_counts = {}
    for line in lines:
        for char in line:
            char_counts[char] = char_counts.get(char, 0) + 1
    return {
        "总字符数": total_chars,
        "每行最大字符数": (max_chars, max_line_index + 1),
        "每行最小字符数": (min_chars, min_line_index + 1),
        "平均每行字符数": avg_chars,
        "总行数": total_lines,
        "字符种类个数": len(char_counts),
        "字符种类及其出现次数": dict(sorted(char_counts.items(), key=lambda item: item[1], reverse=True))
    }

if __name__ == "__main__":
    file_path = "./dataset/doupo_cleaned.txt"
    stats = statistics(file_path)
    for key, value in stats.items():
        print(f"{key}: {value}")
```

