分为节点流（从数据源读入数据或往目的地写出数据）与处理流（对数据执行某种处理），例如

InputStreamReader 为 节点流

BufferedReader 为处理流

![image](https://www.runoob.com/wp-content/uploads/2013/12/iostream2xx.png)

# 面向字符的抽象流类

Reader 和 Writer (其他具体的类就是从它两继承)

具体实现该抽象类的类有：

- FileWriter：

```java
import java.io.*;   
class FileWriterTester {
public static void main ( String[] args ) throws IOException {  
    //main方法中声明抛出IO异常
        String fileName = "C:\\Hello.txt"; 
        FileWriter writer = new FileWriter( fileName );
        writer.write( "Hello!\n"); 
        writer.write( "This is my first text file,\n"  );  
        writer.write( "You can see how this is done.\n" ); 
        writer.write("输入一行中文也可以\n");
        writer.close(); 
    }
}

```

- BufferedWriter:如果需要写入的内容很多，就应该使用更为高效的缓冲器流类BufferedWriter

```java
import java.io.*; 
class BufferedWriterTester {
    public static void main ( String[] args ) throws IOException {
        String fileName = "C:/newHello.txt" ;
        BufferedWriter out = new BufferedWriter(new  FileWriter( fileName ) );
        out.write( "Hello!"  );
        out.newLine() ; 
        out.write( "This is another text file using BufferedWriter,"  );   
        out.newLine(); ;
        out.write( "So I can use a common way to start a newline" ); 
        out.close();
    }
}
```

具体的读文件类有：

- FileReader 类
- BufferedReader

# 面向字节的抽象流类

OutputStream 和 InputStream(其他具体的类就是从它两继承)

具体实现这两抽象类的有：

- FileOutputStream
- BufferedOutputStream
- DataOutputStream（具有：writeInt、writeDouble、writeBytes方法）

# 标准输入输出流对象

- System.in:InputStream类型的，代表标准输入流，默认状态对应于键盘输入
- System.out:PrintStream类型的，代表标准输出流，默认状态对应于显示器输出
- System.err:PrintStream类型的，代表标准错误信息输出流，默认状态对应于显示器输出

# 按类型输入/输出数据

printf方法：

```java
System.out.printf(“%-12s is %2d long”, name, l);
System.out.printf(“value = %2.2F”, value);
```

Scanner:

```java
Scanner s = new Scanner(System.in);
int n = s.nextInt();
//还有下列方法：nextByte(),nextDouble(),nextFloat,nextInt(),nextLine(),nextLong(),nextShort()
```

# 标准输入/输出重新定向

- setIn(InputStream)： 设置标准输入流
- setOut(PrintStream)：设置标准输出流
- setErr(PrintStream)：设置标准错误输出流