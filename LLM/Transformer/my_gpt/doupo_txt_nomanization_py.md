```python
"""
我需要去掉一个小说txt中类似的如：
===第一章 陨落的天才===
===第二章 陨落的天才===

这类的章节分割符


还需要去掉开头空格符
"""

import re

def data_clean(text):
    text = re.sub(r'===.*?===', '', text) # 去掉章节分割符
    text = re.sub(r'^\s+', '', text, flags=re.MULTILINE) # 去掉每行开头的空格符
    text = text.replace('\x7f','') # 去掉不可见字符\x7f
    text=re.sub(r'[\ue000-\uf8ff]','',text) # 去掉私有使用区间的字符
    return text

# 示例用法
if __name__ == "__main__":
    with open("./dataset/doupo.txt", "r", encoding="utf-8") as f:
        text = f.read()
    cleaned_text = data_clean(text)
    with open("./dataset/doupo_cleaned.txt", "w", encoding="utf-8") as f:
        f.write(cleaned_text)%    
```

