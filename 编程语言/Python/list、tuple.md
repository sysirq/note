# list

```python
#!/usr/bin/python3

classmates = ['Michael','Bob','Tracy'] #创建list

print(classmates)

print(len(classmates)) # 打印list的长度

classmates.append("Adam") # 在尾部追加

print(classmates)

classmates.insert(0,"John") # 在指定位置插入元素

print(classmates)

classmates.pop() # 删除尾部元素

print(classmates)
 
classmates.pop(0) # 删除指定元素

print(classmates)
```

# tuple

tuple 和 list 非常类似，但是tuple一旦初始化就不能修改。它没有append()，insert()这样的方法。