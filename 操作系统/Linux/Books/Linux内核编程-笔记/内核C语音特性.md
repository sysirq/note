# volatile

eg: volatile long state;//当读取state字段时，必须重新从内存中加载，及时上一条指令已经将其加载到临时寄存器中。