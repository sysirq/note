# IDC脚本基础

几乎跟C语言一样。

extern 全局的变量，auto 本地变量

eg:

```c
//打印IDA数据库中的所有函数
#include <idc.idc>

static main(){

    auto addr = 0;

    for(addr = get_next_func(addr);addr != -1;addr = get_next_func(addr)){
        msg("%s\n",get_func_name(addr));
    }
}
```

```c
//枚举函数中的指令个数
#include <idc.idc>

static main(){
    auto func_start = get_func_attr(get_screen_ea(),FUNCATTR_START);
    auto func_end;
    auto cur_addr;
    auto count = 0;

    if(func_start != -1){
        func_end = get_func_attr(get_screen_ea(),FUNCATTR_END);
        cur_addr = func_start;
        while(cur_addr != func_end){
            cur_addr = find_code(cur_addr,SEARCH_DOWN|SEARCH_NEXT);
            count++;
        }
        warning("func name:%s , start addr:%X , end addr:%X , instruction count:%d",get_func_name(func_start),func_start,func_end,count);
    }else{
        warning("No function found at location\n");
    }
}
```

```c
//枚举光标所在函数的调用
#include <idc.idc>

static main(){
    auto func_start = get_func_attr(get_screen_ea(),FUNCATTR_START);
    auto func_end;
    auto cur_addr;
    auto target_addr;
    if(func_start != -1){
        func_end = get_func_attr(get_screen_ea(),FUNCATTR_END);
        cur_addr = func_start;
        
        while(cur_addr <= func_end){

            for(target_addr = get_first_cref_from(cur_addr);target_addr != -1;target_addr = get_next_cref_from(cur_addr,target_addr)){
                auto xref = get_xref_type();
                if(xref == fl_CF || xref == fl_CN){
                    msg("callee: %s\n",get_func_name(target_addr));
                }
            }
            cur_addr = find_code(cur_addr,SEARCH_DOWN|SEARCH_NEXT);
        }
    }else{
        warning("No function found at location\n");
    }
}
```

```c
#include <idc.idc>

static main(){
    auto func_start = get_screen_ea();
    auto target_addr;

    if(func_start != -1){
        for(target_addr = get_first_cref_to(func_start);target_addr != -1;target_addr = get_next_cref_to(func_start,target_addr)){
            auto xref = get_xref_type();
            if(xref == fl_CF || xref == fl_CN){
                msg("caller: %s,addr:0x%X\n",get_func_name(target_addr),target_addr);
            }
        }
    }else{
        warning("No function found at location\n");
    }
}
```

# IDC中的数组创建

```c
long create_array(string name);//用指定的名称创建一个数组，并返回对应的句柄，如果存在则返回-1
long get_array_id(string name);//查询指定名称的数组并返回句柄，不存在则返回-1
success set_array_long(long id, long idx, long value);//添加
success set_array_string(long id, long idx, string str);
string or long get_array_element(long tag, long id, long idx);//获取元素
success del_array_element(long tag, long id, long idx);//删除数组中的元素
void delete_array(long id);//删除数组
```

可以通过切片创建数组

```c
For objects, the slice operator denotes a subset of attributes. It can be used to emulate arrays: 

  auto x = object();
  x[0] = value1;
  x[1] = "value2";

```

# 读取和修改数据的函数

```c
long byte(long addr);//从虚拟地址addr处读取1个字节值
long word(long addr);//从虚拟地址addr处读取2个字节值
long dword(long addr);//从虚拟地址addr处读取4个字节值
long qword(long addr);//从虚拟地址addr处读取8个字节值
void patch_byte(long addr,long val);//设置虚拟地址处一个字节
void patch_word(long addr,long val);
void patch_dword(long addr,long val);
void patch_qword(long addr,long val);
bool is_loaded(long addr);//如果addr包含有效数据，则返回1，否则返回0
```

在尝试从数据库中的某个地址读取数据之前，应该调用is_loaded函数，以确定这个地址是否包含任何数据

# 用户交互函数

```c
void msg(string fmt,...);//类似C语言中的printf
void print(...);//在输出窗口中打印每个参数的字符串表示形式
void warning(string format,...);//在对话框中显示一条格式化的消息

// Ask the user to enter a string
//      defval - the default string value. This value
//               will appear in the dialog box.
//      hist   - history id. One of HIST_... constants
//      prompt - the prompt to display in the dialog box
// Returns: the entered string.

string ask_str(string defval, long hist, string prompt);//让用户输入字符串

#define HIST_SEG    1           ///< segment names
#define HIST_CMT    2           ///< comments
#define HIST_SRCH   3           ///< search substrings
#define HIST_IDENT  4           ///< names
#define HIST_FILE   5           ///< file names
#define HIST_TYPE   6           ///< type declarations
#define HIST_CMD    7           ///< commands
#define HIST_DIR    8           ///< directory names (text version only)

// Ask the user to choose a file
//      for_saving- 0: "Open" dialog box, 1: "Save" dialog box
//      mask   - the input file mask as "*.*" or the default file name.
//      prompt - the prompt to display in the dialog box
// Returns: the selected file.

string ask_file(bool for_saving, string mask, string prompt);//让用户选择文件

// Ask the user to enter an address
//      defval - the default address value. This value
//               will appear in the dialog box.
//      prompt - the prompt to display in the dialog box
// Returns: the entered address or BADADDR.

long ask_addr(long defval, string prompt);//让用户输入地址

// Ask the user to enter a number
//      defval - the default value. This value
//               will appear in the dialog box.
//      prompt - the prompt to display in the dialog box
// Returns: the entered number or -1.

long ask_long(long defval, string prompt);

// Ask the user to enter a segment value
//      defval - the default value. This value
//               will appear in the dialog box.
//      prompt - the prompt to display in the dialog box
// Returns: the entered segment selector or BADSEL.

long ask_seg(long defval, string prompt);

// Ask the user a question and let him answer Yes/No/Cancel
//      defval - the default answer. This answer will be selected if the user
//               presses Enter.
//      prompt - the prompt to display in the dialog box
// Returns: -1:cancel, 0-no, 1-ok

long ask_yn(long defval, string prompt);//让用户回答yes no

get_screen_ea();//获取光标所在的虚拟地址
success jumpto(long ea);//跳转到反汇编窗口的指定地址

```

# 字符串操纵函数

```c
string sprintf(string format, ...);//类似C库中的函数
long atol(string val);//将十进制val的字符串转换为对应的整数
long xtol(string val);//将十六进制val的字符串转换为对应的整数
string ltoa(long val,long radix);//以指定的radix（2，8，16）返回val的字符串形式
long ord(string ch);//返回单字符串ch的ASCII值
long strlen(string str);//返回字符串长度
long strstr(string str,string substr);//返回str中substr的索引。如果没有发现则返回-1
```

# 文件输入输出函数

```c
long fopen(string filename,string mode);//返回一个整数文件句柄,出错返回0，该函数与C中的函数类似
void fclose(long handle);
long filelength(long handle);//返回指定文件的长度，出错返回-1

long fgetc(long handle);//从给定文件中读取一个字节，出错返回-1
long fputc(long val,long handle);//写入一个字节到给定文件，出错返回-1
long fprintf(long handle,string format,....);//将一个格式化字符串写入到给定文件中
long writestr(long handle,string str);//将指定的字符串写入到给定的文件中
string readstr(long handle);
long writelong(long handle,long val,long bigendian);//写入
long readlong(long handle,long bigendian);//读取
long writeshort(long handle,long val,long bigendian);
long readshort(long handle,long bigendian);

bool loadfile(long handle,long pos,long addr,long length);//从给定文件的pos位置读取给定的length字节的数据，并将这些数据写入到addr地址开头的数据库中

long savefile(long handle,long pos,long addr,long length);
```

# 操纵数据库名称

```c
string get_name(long ea, long gtn_flags=0);//返回指定地址的名称
success set_name(long ea, string name, long flags=SN_CHECK);//命名一个地址
```

# 处理函数的函数

IDA为进过反汇编的函数分配了大量属性，如函数局部变量区域的大小、函数的参数在运行时栈的大小

```c
long get_func_attr(long ea, long attr);//返回包含给定地址的函数的被请求的属性
string get_func_name(long ea);//返回包含给定地址的函数的名称，如果给定的地址不属于一个函数，返回空字符串
long get_next_func(long ea);//返回给定地址后的下一个函数的起始地址，没有则返回-1
long get_prev_func(long ea);
```

# 交叉引用

```c
//      See sample file xrefs.idc to learn to use these functions.

//      Flow types (combine with XREF_USER!):
#define fl_CF   16              // Call Far
#define fl_CN   17              // Call Near
#define fl_JF   18              // jumpto Far
#define fl_JN   19              // jumpto Near
#define fl_F    21              // Ordinary flow

#define XREF_USER 32            // All user-specified xref types
                                // must be combined with this bit

// Mark exec flow 'from' 'to'
void add_cref(long from, long to, long flowtype);

// Unmark exec flow 'from' 'to'
// undef - make 'to' undefined if no
//        more references to it
// returns 1 - planned to be
// made undefined
long del_cref(long from, long to, int undef);

// The following functions include the ordinary flows:
// (the ordinary flow references are returned first)

// Get first code xref from 'from'
long get_first_cref_from(long From);

// Get next code xref from
long get_next_cref_from(long from, long current);

// Get first code xref to 'to'
long get_first_cref_to(long to);

// Get next code xref to 'to'
long get_next_cref_to(long to, long current);

// The following functions don't take into account the ordinary flows:
long get_first_fcref_from(long from);
long get_next_fcref_from(long from, long current);
long get_first_fcref_to(long to);
long get_next_fcref_to(long to, long current);

// Data reference types (combine with XREF_USER!):
#define dr_O    1                       // Offset
#define dr_W    2                       // Write
#define dr_R    3                       // Read
#define dr_T    4                       // Text (names in manual operands)
#define dr_I    5                       // Informational

// Create Data Ref
void add_dref(long From, long to, long dreftype);

// Unmark Data Ref
void del_dref(long from, long to);

// Get first data xref from 'from'
long get_first_dref_from(long from);
long get_next_dref_from(long From, long current);

// Get first data xref to 'to'
long get_first_dref_to(long to);
long get_next_dref_to(long to, long current);

// returns type of the last xref
// obtained by get_first_.../get_next_...
// functions. Return values
// are fl_... or dr_...
long get_xref_type(void);

```

# 数据库搜索函数

```c
The following functions search for the specified byte
     ea - address to start from
     flag is combination of the following bits:
Returns BADADDR - not found

#define SEARCH_UP       0x00            // search backward
#define SEARCH_DOWN     0x01            // search forward
#define SEARCH_NEXT     0x02            // start the search at the next/prev item
                                        // useful only for find_text() and find_binary()
                                        // for other Find.. functions it is implicitly set
#define SEARCH_CASE     0x04            // search case-sensitive
                                        // (only for bin&txt search)
#define SEARCH_REGEX    0x08            // enable regular expressions (only for txt)
#define SEARCH_NOBRK    0x10            // don't test ctrl-break
#define SEARCH_NOSHOW   0x20            // don't display the search progress

long find_suspop(long ea, long flag);
long find_code(long ea, long flag);
long find_data(long ea, long flag);
long find_unknown(long ea, long flag);
long find_defined(long ea, long flag);
long find_imm(long ea, long flag, long value);
long find_text(long ea, long flag, long y, long x, string str);
                // y - number of text line at ea to start from (0..MAX_ITEM_LINES)
                // x - x coordinate in this line
long find_binary(long ea, long flag, string str);
                // str - a string as a user enters it for Search Text in Core
                //      example:  "41 42" - find 2 bytes 41h, 42h
                // The default radix depends on the current IDP module
                // (radix for ibm pc is 16)



```

# 调试器脚本

### 内存访问功能

```python
idc.read_dbg_byte
idc.read_dbg_word
idc.read_dbg_dword
idc.read_dbg_qword
idc.write_dbg_memory
```

### 寄存器和断点操作

```python
idc.get_reg_value 
idc.set_reg_value
idc.add_bpt
idc.del_bpt
idc.get_bpt_qty # 返回程序中设置的断点的总数
idc.get_bpt_ea # 返回指定断点所在的地址
idc.get_bpt_attr
idc.set_bpt_attr
idc.set_bpt_cond # 将断点条件设置为所提供的条件表达式，这个表达式必须为一个有效的IDC表达式
idc.check_bpt # 获取指定位置的断点状态
```

### 同步控制调试器

使用脚本驱动调试器的基本方法是开始一个调试器操作，然后等待对应的调试器事件代码

```c
long wait_for_next_event(long wfne, long timeout);//在指定的秒数内（-1表示永久）等待一个调试事件
#define resume_process() wait_for_next_event(WFNE_CONT|WFNE_NOWAIT, 0)

success run_to(long ea, long pid=NO_PROCESS, long tid=NO_THREAD);//运行进程，直到到达指定的位置或者遇到一个断点
success step_into(void);
success step_over(void);

success step_until_ret(void);
get_event_XXX
success enable_tracing(long trace_level, long enable);//启用跟踪事件的生成，


```

### 巧用条件断点实现函数hook

```c
#include <idc.idc>

static my_bpt_cond()
{
    auto esp_val,ret;

    print("hook cmp func\n");

    esp_val = get_reg_value("esp");
    ret = read_dbg_dword(esp_val);
    set_reg_value(ret,"eip");
    set_reg_value(0x65,"eax");
    return 0;
}

static main()
{
    auto func = get_name_ea_simple("sub_F61100");
    add_bpt(func);
    set_bpt_cond(func,"my_bpt_cond()");
}
```