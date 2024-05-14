# 对象初始化的步骤

- 将TypeInfo 注册 TypeImpl
- 实例化ObjectClass
- 实例化Object
- 添加Property

# TypeInfo数据结构

用户如果需要定义类，则必须创建一个TypeInfo的类型。然后调用type_register_static转换为TypeImpl

# TypeImpl

由TypeInfo转换而来

# ObjectClass

所有类的基类，通过调用type_initialize创建

# Object

所有对象的base Object。其拥有属性ObjectClass

# 自制对象创建过程

```c
////////////////////////////////////////////////////////////////////////////////////////////
typedef struct MyState{ //一般用来保存对象的数据 
	Object parent;
	int age;
}MyState;

typedef struct MyClass{//一般保存类函数指针
	ObjectClass parent_class;
	void (*set_age)(MyState *ms,int age);
	int (*get_age)(MyState *ms);
}Myclass;

#define MY_CLASS(klass) \
    OBJECT_CLASS_CHECK(struct MyClass, (klass), "My")
#define MY(obj) \
    OBJECT_CHECK(struct MyClass, (obj), "My")
#define MY_GET_CLASS(obj) \
    OBJECT_GET_CLASS(struct MyClass, (obj), "My")

static void mystate_set_age(MyState *ms,int age)
{
	ms->age=age;
}

static int mystate_get_age(MyState *ms)
{
	return ms->age;
}

static void my_class_init(ObjectClass *klass, void *data)
{
	struct MyClass *ms = MY_CLASS(klass);
	ms->get_age = mystate_get_age;
	ms->set_age = mystate_set_age;
}

static const TypeInfo my_type = {
		.name = "My",
		.parent = TYPE_OBJECT,
		.class_size = sizeof(struct MyClass),
		.class_init = my_class_init,
		.instance_size = sizeof(struct MyState),
};

static void my_type_init(void)
{
    type_register_static(&my_type);
}

type_init(my_type_init);

int main(int argc, char **argv, char **envp)
{
	module_call_init(MODULE_INIT_QOM);

	struct MyClass *ms = MY_CLASS(object_class_by_name("My"));//获得class
	if(ms){
		printf("find myclass \n");
	}else{
		printf("find myclass error\n");return 1;
	}

	const char *cname = object_class_get_name(ms);
	printf("name:%s\n",cname);

	struct MyState *state = MY(object_new(cname));//创建对象
	if(state){
		printf("create object success\n");
	}else{
		printf("create object success\n");return 2;
	}
	ms->set_age(state,20);

	printf("age:%d\n",ms->get_age(state));
}
///////////////////////////////////////////////////////////////////////////
```

输出为:

```c
find myclass 
name:My
create object success
age:20
```

# 资料

QOM模型的数据结构

https://blog.csdn.net/u011364612/article/details/53485856

QEMU设备的对象模型QOM

https://juniorprincewang.github.io/2018/07/23/qemu%E6%BA%90%E7%A0%81%E6%B7%BB%E5%8A%A0%E8%AE%BE%E5%A4%87/

QEMU学习笔记——QOM(Qemu Object Model)

https://www.binss.me/blog/qemu-note-of-qemu-object-model/

qemu如何实现面向对象模型QOM（代码讲解）

https://www.twblogs.net/a/5b8568e12b71775d1cd2ef0b/zh-cn