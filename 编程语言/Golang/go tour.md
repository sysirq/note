# 如何判断变量是分配在栈（stack）上还是堆（heap）上

Golang 中的变量只要被引用就一直会存活

通常情况下：

- 栈上：函数调用的参数、返回值以及小类型局部变量大都会被分配到栈上，这部分内存会由编译器进行管理。 无需 GC 的标记。
- 堆上：大对象、逃逸的变量会被分配到堆上，分配到堆上的对象。Go 的运行时 GC 就会在 后台将对应的内存进行标记从而能够在垃圾回收的时候将对应的内存回收，进而增加了开销。

eg:

```go
func main() {
	a := make([]int, 10000)
	b := make([]int, 1000)
}
```

```go
go run -gcflags "-m -l" main.go (-m打印逃逸分析信息，-l禁止内联编译)

./main.go:22:11: make([]int, 10000) escapes to heap //无法被一个执行栈装下，即便没有返回，也会直接在堆上分配；

./main.go:23:11: main make([]int, 1000) does not escape //对象能够被一个执行栈装下，变量没有返回到栈外，进而没有发生逃逸。
```

golang 变量存储在堆上还是栈上由内部实现决定而和具体的语法没有关系。非指针小对象通常保存在栈上，大对象保存在堆上。至于指针保存在堆上还是栈上，要进行逃逸分析：

我们得出了指针必然发生逃逸的三种情况：

- 在某个函数中new或字面量创建出的变量，将其指针作为函数返回值，则该变量一定发生逃逸（构造函数返回的指针变量一定逃逸）；
- 被已经逃逸的变量引用的指针，一定发生逃逸；
- 被指针类型的slice、map和chan引用的指针，一定发生逃逸；

### 资料

如何判断golang变量是分配在栈（stack）上还是堆（heap）上？

https://zhuanlan.zhihu.com/p/523195006

# go 命令 

go version:go当前版本查看

go env : 环境变量查看，重要的是GOPATH,GOBIN

# go vscode debug

安装go插件

安装delve调试工具（https://github.com/go-delve/delve/tree/master/Documentation/installation）

# Packages,variables,and functions

### Packages

- Every Go program is made up of packages
- Programs start running in package main
- In Go,a name is exported if it begins with a capital letter(upper letter).

### Functions

- type comes after the variable name.
```go
    var i int
    var (
        j int 
        k int
    )
```
- When two or more consecutive named function parameters share a type,you can omit the type from all but the last.
```go
    var i,j int
```
- A function can return any number of results

```go
func add_sub(a,b int)(int,int){
    return a+b,a-b
}
```

### Variables

- The var statement declares a list of variables
- Inside a function,the := short assigment statement can be used in place of a var declaration with implicit type.
- Variables declared without an explicit initial value are given their zero value.
- The expression T(v) converts the value v to the type T.Go assignment between items of different type requires an explicit conversion.
- Constants are declared like variables,but with the const keyword(Constants cannot be declared using the := syntax)
```go
const pi=3.14
```
# Flow control statements: for,if,else,switch and defer

### for

- unlike other languages like C,java there are no  parentheses surrounding the three components of the for statement and the braces {} are always required.
```go
for i:=10;i<10;i++{
    fmt.Println(i)
}
```
- The init statement will often be a short variable declaration,and the varaibles there are visible only in the scope of the for statement
- The init and post statements are optional.
- You can drop the semicolons:C's while is spelled for in Go.
- If you omit the loop condition it loops forever,so an infinite loop is compactly expressed.


### If

- Go's if statements are like its for loops;the expression need not be surrounded by parentheses() but the braces {} are required.
- Like for,the if statement can start with a short statement to execute before the condition
- Variables declared inside an if short statement are also available inside any of the else blocks.

sort:
```Go
package main

import (
	"fmt"
)

func main(){
	arr := []int{1,5,3,2,6,3,4,8,7,0}
	
	for i:=0;i<len(arr);i++{
		fmt.Printf("%d ",arr[i]);
	}
	fmt.Printf("\nSorting\n");
	
	for i:=0;i<len(arr);i++{
		for j:= i+1;j<len(arr);j++{
			if arr[i]>arr[j]{
				arr[i],arr[j] = arr[j],arr[i]
			}
		}
	}
	
	for i:=0;i<len(arr);i++{
		fmt.Printf("%d ",arr[i]);
	}
	fmt.Printf("\n");
}
```

### Switch

- In effect,the break statement that is needed at the end of each case in those languages(C,C++) is provided automatically in Go.（fallthrough）
- Go's switch cases need not be constants,and the values involved need not be integers
- Switch cases evaluate cases from top to bottom,stopping when a case succeeds.
- Switch without a condition is the sames as switch true.

### Defer

- A defer statement defers the execution of a function until the surrounding function returns.The deferred call's arguments are evaluated immediately.
- Deferred function calls are pushed onto stack.When a function returns,its deferred calls are executed in last-in-first-out-order.

# More types:structs,slices,and maps.

### Pointers

- The type *T is a pointer to a T value.Its zero value is nil.
- Unlike C,Go has no pointer arithmetic

### Structs

- A struct is a collection of fields.
- Struct fields are accessed using a dot.

```go
type Vertex struct{
    X int
    Y int
}
```

### Pointers to struct

- To access the field X of a struct when we have the struct pointer p we could write (*p).X.However,that notation is cumbersome,so the language permits us instead to write just p.X,without the explicit dereference.

### Struct Literals

- A struct literal denotes a newly allocated struct value by listing the values of its fields.You can list just a subset of fields by using the Name: syntax.

### Arrays

- The type [n]T is an array of n values of type T.

### Slices

- An array has a fixed size.A slice ,on the other hand , is a dynamically-sized,flexible view into the elements of an array.
- The type []T is a slice with elements of type T.
- A slice if formed by specifying two indices,a low and high bound,separated by a colon:a[low:high],This selects a half-open range which includes the first element,but excludes the last one.

### Slices are like reference to arrays

- A slice does not store any data,it just describes a section of an underlying array.
- Changing the elements of a slice modifies the corresponding elements of its underlying array.
- Other slices that share the same underlying array will see those changes.

### Slice literals

- A slice literal is like an array literal without the length

### Slice defaults

- When slicing,you may omit the high or low bounds to use their defaults instead.The default is zero for the low bound and the length of the slice for the high bound.

### Slice length and capacity

- A slice has both a length and a capacity.
- The length of a slice is the number of elements it contains
- The capacity of a slice is the number of elements in the underlying array,counting from the first element in the slice.
- The length and capacity of a slice s can be obtained using the expression len(s) and cap(s)

### Nil Slices

- The zero value of a slice is nil.

### Creating a slice with make

- Slices can be created with the built-in make function;this is how you create dynamically-sized arrays.
- The make function allocates a zeroed array and returns a slice that refers to that array:
```go
a:=make([]int,5)//len(a)=5
```
- To specify a capacity,pass a third argument to make:

### Appending to a slice

- it is common to append new elements to a slice,and so Go provides a built-in append function.
```go
func append(s []T,vs ....T)[]T
```
- The resulting value of append is a slice containing all the elements of the original slice plus the provided values.
- If the backing array of s is too small to fit all the given values a bigger array will be allocated.The returned slice will point to the newly allocated array.

### Range

- The range form of the loop iterates over a slice or map.
- When ranging over a slice,two values are returned for each iteration.The first is the index,and the second is a copy of the element at that index.
- You can skip the index or value by assigning to _.
- If you only want the index,drop the , value entirely.

```go
	s := make([]int, 0, 5)

	for i := 20; i < 30; i++ {
		s = append(s, i)
	}

	for k, _ := range s {
		fmt.Println(k)
	}
```

### Maps

- A map maps keys to values.
```go
make(map [string]int)
```
- The make function returns a map of the given type,initialized and ready for use.
- Delete an element:
```go
delete(m,key)
```
- Test that a key is present with a two-value assignment:
```go
elem,ok = m[key]
```
if key is not in the map,then elem is the zero value for the map's element type.


### Function values

- Functions are values too.They can be passed around just like other values.
- Function values may be used as function arguments and return values

```go
func my_test(fn func(int, int) int) int {
	return fn(2, 3)
}

func My_Print() {
	f := func(x, y int) int {
		return x + y
	}

	k := my_test(f)

	fmt.Println(k)
}

```

### Function closures

- Go functions may be closures.A closure is a function value that referenes variables from outside its body.The function may access and assign to the referenced variables;in this sense the function is "bound" to the variables



# Methods and interfaces

### Method

- Go does not have classes.However,you can define methods on types.
- A method is a function with a special receiver argument.
- The receive appears in its own argument list between the func keyword and the method name.
- Remember:a method is just a function with a receiver argument.
- You cannot declare a method with a receiver whose type is defined in another package(which includes the built-in types such as int)
- You can declare methods with pointer receivers.This means the receiver type has the literal syntax *T for some type T.(Also,T cannot itself be a pointer such as *int.)

```go
type Vertex struct {
	X, Y float64
}

func (v Vertex) Abs() float64 {
	return math.Sqrt(v.X*v.X + v.Y*v.Y)
}

func My_Print() {
	v := Vertex{3, 4}
	fmt.Println(v.Abs())
}
```

### Methods and pointer indirection

- methods with pointer receivers take either a value or a pointer as the receiver when they are called.(The equivalent thing happends in the reverse direction)

### Choosing a value or pointer receiver

- There are two reasons to use a pointer receiver.
- The first is so that the method can modify the value that its receiver points to.
- The second is to avoid copying the value on each method call.This can be more efficient if the receiver is a large struct.
- In general,all methods on a given type should have either value or pointer receivers,but not a mixture of both.

### Interfaces

- An interface type is defined as a set of method signatures.
- A value of interface type can hold any value that implements those methods.

### Interfaces are implemented implicitly

- A type implements an interface by implementing its methods.There is no explicit declaration of intent,no "implements" keyword.

### Interface values

- Under the hood,interface values can be thought of as a tuple of a value and a concrete type:
- An interface value holds a value of a specific underlying concrete type.
- Calling a method on an interface value executes the method of the same name on its underlying type.

### Interface values with nil underlying values

- If the concrete value inside the interface itself is nil,the method will be called with a nil receiver.
- Note that an interface value that holds a nil concrete value is itself non-nil

### Nil interface value

- A nil interface value holds neither value nor concrete type.

### The empty interface

- The interface type that specifies zero methods is known as the empty interface.
- An empty interface may hold values of any type.
- Empty interfaces are used by code that handles values of unknown type.

### Type assertions

- A type assertion provides access to an interface value's underlying concrete value.
```go
t := i.(T)
```
This statement asserts that the interface value i holds the concrete type T and assigns the underlying T value to the variable t.

```go
t, ok := i.(T)
```

If i holds a T, then t will be the underlying value and ok will be true.

If not, ok will be false and t will be the zero value of type T, and no panic occurs.

### Type switches

- A type switch is a construct that permits serveral type assertions in series.
```
switch v := i.(type){
    case T:
        //here v has type T
    default:
        //no match
}
```

A type switch is like a regular switch statement,but the cases in a type switch specify type(not value),and those values are compared against the type of the value held by the given interface value.

The declaration in a type switch has the same syntax as a type assertion i.(T),but the specific type T is replaced with the keyword type.

### Stringers

one of the most ubiquitous interfaces is Stringer defined by the fmt package.
```go
type Stringer interface{
    String() string
}
```
A Stringer is a type that can describe itself as string.The fmt package look for this interface to print values.

### Errors

Go programs express error state with error values.

The error type is a built-in interface similar to fmt.Stringer:

```go
type error interface {
    Error() string
}
```

(As with fmt.Stringer, the fmt package looks for the error interface when printing values.)

- A nil error denotes success;a non-nil error denotes failure.

### Reader

- The io package specifies the io.Reader interface,which represents the read end of a stream of data.
- The Go standard library contains many implementations of these interfaces,including files,network connections,compressors,ciphers,and others.
- The io.Reader interface has a Read method:
```Go
func (T)Read(b []byte)(n int,err error)
```
Read populates the given byte slice with data and returns the number if bytes populated and an error value.It returns an io.EOF error when the stream ends

### Image 

Package image defines the Image interface
```Go
package image
type Image interface{
    ColorModel() color.Model
    Bounds() Rectangle
    At(x,y int) color.Color
}
```

# generics

Go functions can be written to work on multiple types using type parameters. The type parameters of a function appear between brackets, before the function's arguments.

```go
func Index[T comparable](s []T, x T) int
```

This declaration means that s is a slice of any type T that fulfills the built-in constraint comparable. x is also a value of the same type.

# Concurrency

### Goroutines

A goroutine is a lightweight thread managed by by the Go runtime.
```go
go f(x,y,z)
```
starts a new goroutine running
```go
f(x,y,z)
```

Goroutines run the same address space,so access to shared memory must be synchronized.The sync package provides useful primitives,althought you wan't need them much in Go as there are other primtives.

### Channels

 - Channels are a typed conduit through which you can send and receive values with the channel operator,<-
 - Like maps and slices,channels must be created before use:
 ```go
 ch:=make(chan int)
 ```
 - By default,sends and receives block until the other side is ready.This allows goroutines to synchronize without explicit locks or condition variables.


### Buffered Channels

- Channels can be buffered.Provide the buffer length as the second argument to make to initialize a buffered channel:
```go
ch := make(chan int,100)
```
- Sends to a buffered channel block only when the buffer is full.Receives block when the buffer is empty.

### Range and Close

- A sender can close a channel to indicate that no more values will be sent.Receivers can test whether a channel has been closed by assigning a second parameter to the receive expression:
```go
v,ok:=<-ch

//close(c) //close channel
```
- The loop for i:= range c receives values from the channel repeatedly until it is closed.

### Select

- The select statement lets a goroutine wait on multiple communication operations.
- A select blocks until one of its cases can run,then it executes that case.It chooses one at random if multiple are ready.
```go
	tick := time.Tick(1000 * time.Millisecond)

	for {
		select {
		case <-tick:
			fmt.Println("tick")
		default:
			fmt.Println(".")
			time.Sleep(50 * time.Millisecond)
		}
	}
```


### Default Selection

- The default case in a select is run if no other case is ready.
- Use a default case to try a send or receive without blocking
```go
select {
case i := <-c:
    //use i
default:
    //receiving frim c would block
}
```

### sync.Mutex

What if we just want to make sure only one goroutine can access a variable at a time to avoid conflicts

The concept is called mutual exclusion,and the conventional name for the data structure that provides it is mutex

Go's standard libaray provides mutual exclusion with sync.Mutext and its two methods:
```go
mux sync.Mutex

mux.Lock

mux.Unlock
```

# 资料
1.How to Write Go Code

https://golang.org/doc/code.html

2.A Tour of Go

https://tour.golang.org/list

3.Effective Go

https://golang.org/doc/effective_go.html

4.Visit the documentation page for a set of in-depth articles about the Go language and its libraries and tools.

https://golang.org/doc/#articles
