# 核心（伪随机数算法）

```c
// initialize the mersenne twister
void mersenne_init(unsigned int seed, unsigned int MT[])
{
	MT[0] = seed;

	for(MT[0x270] = 1;MT[0x270] < 0x270;MT[0x270]++)
		MT[MT[0x270]] = ((MT[MT[0x270] - 1] >> 0x1E) ^ MT[MT[0x270] - 1]) * 0x6C078965 + MT[0x270];
}

// return the next random value from the twister
unsigned int mersenne_gen(unsigned int MT[])
{
	if(MT[0x270] >= 0x270)
	{
		unsigned int xor;

		for(int i = 0;i < 0x270;i++)
		{
			xor = ((MT[i] ^ MT[(i + 1) % 0x270]) & 0x7FFFFFFF) ^ MT[i];
			MT[i] = MT[(i + 0x18D) % 0x270] ^ (xor >> 1);
			if(xor & 1)
				MT[i] ^= 0x9908B0DF;
		}

		MT[0x270] = 0;
	}

	unsigned int raw;
	raw = MT[MT[0x270]];
	MT[0x270] = MT[0x270] + 1;
	raw ^= (raw >> 0xB);
	raw ^= (raw & 0x0FF3A58AD) << 0x7;
	raw ^= ((raw & 0xFFFF0000) | (raw & 0x0000DF8C)) << 0xF;
	return raw ^ (raw >> 0x12);
}

// convert the raw twister value into a value within the range [min, max] inclusive
int mersenne_range(unsigned int MT[], int min, int max)
{
	return (mersenne_gen(MT) & 0x0FFFFFFF) / (float) 0x10000000 * (max - min + 1) + min;
}

int main()
{//MT19937 mersenne twister
	unsigned int MT[0x271];
	int rand;
	
	mersenne_init(0xdeadbeef, MT);
	
	rand = mersenne_range(MT, 0, 200);
	return 0;
}
```

# 资料

DGA域名的今生前世：缘起、检测、与发展

https://www.secrss.com/articles/14369

What Are Domain Generation Algorithms?

https://www.akamai.com/glossary/what-are-dgas

domain_generation_algorithms

https://github.com/baderj/domain_generation_algorithms

Android.Vo1d.1

https://vms.drweb.co.jp/virus/?i=28921655

Android.Vo1d.3

https://vms.drweb.co.jp/virus/?i=28921664