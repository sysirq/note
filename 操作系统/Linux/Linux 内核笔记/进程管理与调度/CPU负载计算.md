计算一个CPU的负载，最简单的方法是计算CPU上就绪队列上所有进程的权重。但仅考虑优先级权重是有问题的，因为没有考虑该进程的行为。因此从Linux 3.8 内核以后进程的负载计算不仅考虑权重，而且跟踪每个调度实体的负载情况，该方法称为 PELT (Pre-entity Load Tracking)。调度实体数据结构中有一个struct sched_avg用于描述进程的负载。

```c
struct sched_avg {
	/*
	 * These sums represent an infinite geometric series and so are bound
	 * above by 1024/(1-y).  Thus we only need a u32 to store them for all
	 * choices of y < 1-2^(-32)*1024.
	 */
	u32 runnable_avg_sum, runnable_avg_period;
	u64 last_runnable_update;
	s64 decay_count;
	unsigned long load_avg_contrib;
};
```

考虑到历史数据对负载的影响，采用衰减系数来计算平均负载。

runnable_avg_sum:调度实体在就绪队列里可运行状态下总的衰减累加时间。

runnable_avg_period:调度实体在系统中总的衰减累加时间。

load_avg_contrib:进程平均负载的贡献度

cfs_rq数据结构中的成员 runnable_load_avg用于累加在该队列上所有调度实体的load_avg_contrib总和。

# 计算方法

在一个周期内对系统负载的贡献除了权重外，还有在周期内可运行的时间，包括运行时间或等待运行的时间。

一个理想的计算方法：统计多个实际的周期，并使用一个衰减系数来计算过去的周期对负载的贡献。假设Li是调度实体在第i个周期内的负载贡献，那么一个调度实体的总负载和计算如下:

```
L = L0 + L1*y + L2*y^2 + L3*y^3 + ... + L32*y^32 + ...
```

其中，y是一个预先定义好的衰减系数,y^32约等于0.5，因此统计过去第32个周期的负载可以被简单地认为负载减半。

该公式还有一个简化计算方式：只需要过去周期贡献总和乘以衰减系数y，并加上当前时间点的负载L0即可。

内核定义了表runnable_avg_yN_inv来方便使用衰减因子：

```c
static const u32 runnable_avg_yN_inv[] = {
	0xffffffff, 0xfa83b2da, 0xf5257d14, 0xefe4b99a, 0xeac0c6e6, 0xe5b906e6,
	0xe0ccdeeb, 0xdbfbb796, 0xd744fcc9, 0xd2a81d91, 0xce248c14, 0xc9b9bd85,
	0xc5672a10, 0xc12c4cc9, 0xbd08a39e, 0xb8fbaf46, 0xb504f333, 0xb123f581,
	0xad583ee9, 0xa9a15ab4, 0xa5fed6a9, 0xa2704302, 0x9ef5325f, 0x9b8d39b9,
	0x9837f050, 0x94f4efa8, 0x91c3d373, 0x8ea4398a, 0x8b95c1e3, 0x88980e80,
	0x85aac367, 0x82cd8698,
};
```
该表对应衰减因子乘以2^32

内核中 decay_load 函数用于计算第n个周期的衰减值(val * y^n)。

内核维护了一个表runnable_avg_yN_sum,已经预先计算好了如下公式的值：

```
runnable_avg_yN_sum[] = 1024*(y + y^2 + y^3 + ... +y^n)

1<=n<=32
```

1024微秒表示为一个周期

```c
static const u32 runnable_avg_yN_sum[] = {
	    0, 1002, 1982, 2941, 3880, 4798, 5697, 6576, 7437, 8279, 9103,
	 9909,10698,11470,12226,12966,13690,14398,15091,15769,16433,17082,
	17718,18340,18949,19545,20128,20698,21256,21802,22336,22859,23371,
};
```

__compute_runnable_contrib会使用该表来计算连续n个周期的负载累加贡献值。


# __update_entity_runnable_avg

# update_entity_load_avg

该函数计算进程最终的负载贡献度 load_avg_contrib.公式为:

```c
load_avg_contrib = (runnable_avg_sum * weight)/runnable_avg_period
```

一个调度实体的平均负载和以下3个因素有关:

- 调度实体的权重值 weight
- 调度实体的可运行状态下的总衰减累加时间runnable_avg_sum
- 调度实体在调度器中的总衰减累加时间runnable_avg_period


