# 基本数据类型

- 数值型
- 字符型
- 布尔型
- 字符串
- 对象

### 数组

基本类型数组的每个元素都是一个基本类型的变
量；引用类型数组的每个元素都是对象的的引用

```java
int[] arr = new int[5];
```

### 数组复制

```java
public static void arraycopy(Object source , int srcIndex , 
Object dest , int destIndex , int length ) 

System.arraycopy(args, 0, arr, 0, 0);
```


# 类与对象

Java仅仅支持单继承

### 类声明

语法：

```java
[public][abstract|final]class 类名称
[extends 父类名称]
[implements 接口名称列表]
{
    数据成员声明及初始化；
    方法声明及方法体
}
```

### 数据成员声明

```
[public | protected | private] 
[static][ final][transient] [volatile]
数据类型 变量名1[=变量初值],  变量名2[=变量初值], ... ;


▫ public、protected、private 为访问控制符。
▫ static指明这是一个静态成员变量（类变量）。
▫ final指明变量的值不能被修改。
▫ transient指明变量是不需要序列化的。
▫ volatile指明变量是一个共享变量。
```

### 方法成员

```
[public | protected | private] 
[static][ final][abstract] [native] [synchronized]
返回类型 方法名([参数列表]) [throws exceptionList]
{
    方法体
}

• public、protected、private 控制访问权限。
• static指明这是一个类方法（静态方法）。
• final指明这是一个终结方法。
• abstract指明这是一个抽象方法。
• native用来集成java代码和其它语言的代码。
• synchronized用来控制多个并发线程对共享数据的访问。
• throws exceptionList:抛出异常列表
```

### 构造函数

### 析构函数

finalize()方法

# 类的继承

所有Java类的直接或间接超类为Object类

### 属性的隐藏

子类中声明了与超类中相同的成员变量名

- 从超类继承的变量将被隐藏
- 子类拥有了两个相同名字的变量，一个继承自超类，另一个由自己声明
- 当子类执行继承自超类的操作时，处理的是继承自超类的变量，而当子类执行它自己声明的方法时，所操作的就是它自己声明的变量

本类中声明的方法使用“super.属性”访问从超类继承的属性

### 方法覆盖

如果子类不需使用从超类继承来的方法的功能，则可以声明自己的同名方法，称为方法覆盖

- 覆盖方法的返回类型，方法名称，参数的个数及类型必须和被覆盖的方法一摸一样
- 只需在方法名前面使用不同的类名或不同类的对象名即可区分覆盖方法和被覆盖方法
-  覆盖方法的访问权限可以比被覆盖的宽松，但是不能更为严格

调用被覆盖的方法：super.overriddenMethodName();

### 终结类与终结方法

- 有些类，或类的方法从安全的角度或者算法的角度不希望被修改，就可以设为终结类、终结方法
- 终结类不可以被继承（扩展）
- 终结方法不可以被覆盖

# 抽象类

代表一个抽象概念的类；规定整个类家族都必须具备的属性和行为。

# Object类

所有类的直接或间接超类，处在类层次最高点，包含了所有Java类的公共属性

### Object类的主要方法

```
• public final Class getClass()  
▫ 获取当前对象所属的类信息，返回Class对象。
• public String toString() 
▫ 返回表示当前对象本身有关信息的字符串对象。
• public boolean equals(Object obj)  
▫ 比较两个对象引用是否指向同一对象，是则返回true，否则返回false。
• protected Object clone( )  
▫ 复制当前对象，并返回这个副本。
• Public int hashCode()   
▫ 返回该对象的哈希代码值。
• protected void finalize() throws Throwable 
▫ 在对象被回收时执行，通常完成的资源释放工作
```

# 枚举类

```
[public] enum 枚举类型名称[implements 接口名称列表]
{  
    枚举值；
    变量成员声明及初始化；
    方法声明及方法体；
}
```

- 枚举类中也可以声明构造方法和其他用于操作枚举对象的方法

### 枚举类的特点

- 枚举定义实际上是定义了一个类；
- 所有枚举类型都隐含继承（扩展）自java.lang.Enum，因此枚举类型不能再继承其他任何类；
- 枚举类型的类体中可以包括方法和变量；
- 枚举类型的构造方法必须是包内私有或者私有的。定义在枚举开头的常量会被自动创建，不能显式地调用枚举类的构造方法。

### 枚举类型的默认方法

- 静态的values()方法用于获得枚举类型的枚举值的数组；
- toString方法返回枚举值的字符串描述
- valueOf方法将以字符串形式表示的枚举值转化为枚举类型的对象；
- ordinal方法获得对象在枚举类型中的位置索引。

eg:

```java
public enum Planet {
    MERCURY (3.303e+23, 2.4397e6),
    VENUS   (4.869e+24, 6.0518e6),
    EARTH   (5.976e+24, 6.37814e6),
    MARS    (6.421e+23, 3.3972e6),
    JUPITER (1.9e+27,   7.1492e7),
    SATURN  (5.688e+26, 6.0268e7),
    URANUS  (8.686e+25, 2.5559e7),
    NEPTUNE (1.024e+26, 2.4746e7);
    private final double mass;   // in kilograms
    private final double radius; // in meters
    Planet(double mass, double radius) {
        this.mass = mass;
        this.radius = radius;
    }
}
```

# 包

### 引入包

为了使用其它包中所提供的类，需要使用import语句引入所需要的类

格式：

```java
import package1[.package2...]. (classname |*);

▫ package1[.package2...]表明包的层次，对应于文件目录；
▫ classname指明所要引入的类名；
▫ 如果要引入一个包中的所有类，可以使用星号（*）来代替类名。
```

### 编译单元

一个Java源代码文件称为一个编译单元

一个编译单元中只能有一个public类，该类名与文件名相同，编译单元中的其他类往往是public类的辅助类，经过编译，每个类都会
产一个class文件。

一个Java源代码文件称为一个编译单元，由三部分组成：

- 所属包的声明（省略，则属于默认包）
- Import （引入）包的声明，用于导入外部的类
- 类和接口的声明。

# 接口

可以看做是一个“纯”抽象类，它只提供一种形式，并不提供实现

接口中可以规定方法的原型：方法名、参数列表以及返回类型，但不规定方法主体

也可以包含基本数据类型的数据成员，但它们都默认为==static和final==

### 接口的语法

```java
[接口修饰符] interface 接口名称 [extends 父接口名]{
    ...//方法的原型声明或静态常量
}
```

接口的数据成员一定要有初值，且此值将不能再更改，可以省略final关键字

接口中的方法必须是“抽象方法”，不能有方法体，可以省略public及abstract关键字

# 类型转换

### 规则

引用变量的类型转换：

- 将引用转换为另一类型的引用，并不改变对象本身的类型
- 只能被转为：1.任何一个（直接或间接）超类的类型（向上转型），2.对象所属的类（或其超类）实现的一个接口（向上转型），3.被转为引用指向的对象的类型（唯一可以向下转型的情况）
-  当一个引用被转为其超类引用后，通过他能够访问的只有在超类中
声明过的方法

### 方法查找

- 实列方法的查找

从对象创建时的类开始，沿类层次向上查找

```java
// Object=>Person=>Empioyee=>Mananger
//Empioyee与Mananger都有computePay方法

Manager man = new Manager(); 
Employee emp1 = new Employee(); 
Employee emp2 = (Employee)man; 
emp1.computePay();     // 调用Employee类中的computePay()方法
man.computePay(); // 调用Manager类中的computePay()方法
emp2.computePay();     // 调用Manager类中的computePay()方法
```

- 类方法的查找

总是在引用变量声明时所属的类中进行查找

```java
Manager  man = new Manager(); 
Employee emp1 = new Employee(); 
Employee emp2 = (Employee)man; 
man.expenseAllowance();          //in Manager 
emp1.expenseAllowance();         //in Employee 
emp2.expenseAllowance();         //in Employee!!!
```

# 异常

自定义的所有异常类都必须是Exception的子类

声明语法如下：

```java
public class MyExceptionName extends SuperclassOfMyException { 
    public MyExceptionName() { 
        super("Some string explaining the exception"); 
    } 
}
```