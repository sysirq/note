Computer system performance depends on the memory system as well as the processor microarchitecture.

![image](images/3C6AC6411C454F2FB54FE4815548C8BBclipboard.png)

# Memory System Performance Analysis

![image](images/8AF30C2F4B5B4AF8AA00957F7FB800E1clipboard.png)

Average memory access time(AMAT) is the average time a processor must wait for memory per load or store instruction.In the typical computer system,the processor first looks for the data in the cache.If the cache misses,the processor then looks in main memory.If the main memory misses,the processor accesses virtual memory on the hard disk.

![image](images/E4160D09BE6246C2B3DA9AE3DE3F4FB8clipboard.png)
![image](images/B7B477A31D254422B7A027ABA3F73BBFclipboard.png)

# Caches

When the processor attempts to access data,it first checks the cache for the data.If the cache hits,the data is available immediately.If the cache misses,the processor fetches the data from main memory and places it in the cache for future use.

Caches are categorized based on the number of blocks in a set.

![image](images/C43B815428F14C28B1EC6D73F9654CDCclipboard.png)

### direct mapped cache

![image](images/BEF46F00CF454C22A3A042C21EE02ECDclipboard.png)

![image](images/0F1E305FF5994B1EBD5EE28D9846785Aclipboard.png)

### Multi-way Set Associative Cache

![image](images/109352F69FF840F8AFF609F600A40171clipboard.png)

### Putting it All Together

Caches are organized as two-dimensional arrays.The rows are called sets,and the columns are called ways.Each entry in the array consists of a data block and its associated valid and tag bits.Caches are characterized by:

- capacity C
- block size b
- number of blocks in a set

Each address in memory maps to only one set but can be stored in any of the ways.

Increasing the associativity N usually reduces the miss rate caused by conflicts.But higher associativity requires more tag comparators.Increasing the block size b take advantage of spatial locality to reduce the miss rate.However,it decrease the number of sets in a fixed sized cache and therefore could lead to more conflicts.It also increases the miss penalty.

- compulsory misses
- capacity misses
- conflict misses

# IO Introduction

A processor accesses an IO device using the address and data busses in the same way that it accesses memory.

![image](images/37B593FDDB6D4958BD0C687B8010995Fclipboard.png)

An address decoder determines which device communicates with the processor.It uses the Address and MemWrite signals to generate control singals for the reset of the hardware.The ReadData multiplexer selects between memory and the various IO devices.Write-enabled registers hold the values written to the IO devices.

# PC IO Systems