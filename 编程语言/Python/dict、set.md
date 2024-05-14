Python内置了字典dict的支持，dict全称dictionary，其他语言中也称为map，使用键-值存储

如果key不存在，dict就会报错：

```python
>>> d['Thomas']
Traceback (most recent call last):
  File "<stdin>", line 1, in <module>
KeyError: 'Thomas'
```

要避免key不存在的错误，有两种办法，一是通过in判断key是否存在

二是通过dict提供的get()方法，如果key不存在，可以返回None，或者自己指定的value.

要删除一个key，用pop(key)方法，对应的value也会从dict中删除：

# set

set 和 dict类似，也是一组key的集合，但不存储value。由于key不能重复，所以，在set中，没有重复的key。 

要创建一个set，需要提供一个list作为输入集合：

```
>>> s = set([1, 2, 3])
>>> s
{1, 2, 3}
```

add(key)

remove(key)