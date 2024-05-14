# Concurrency and Its Management

Race condition can often lead to system crashes, memory leak,corrupted data,or security problem as well

- avoid the use of global variables

# The Linux Semaphore Implementation

#### Semaphore

```C
#include <linux/semaphore.h>

void sema_init(struct semaphore *sem,int val);

void down(struct semaphore *sem);

int down_interruptible(struct semaphore *sem);

int down_trylock(struct semaphore *sem);

void up(struct semaphore *sem);
```

### Reader/Writer Semaphore

```c
#include <linux/rwsem.h>

void init_rwsem(struct rw_semaphore *sem);

void down_read(struct rw_semaphore *sem);

int down_read_trylock(struct rw_semaphore *sem);

void up_read(struct rw_semaphore *sem);



void down_write(struct rw_semaphore *sem);

int down_write_trylock(struct rw_semaphore *sem);

void up_write(struct rw_semaphore *sem);

void downgrade_write(struct rw_semaphore *sem);
```

# Completions

```c
#include <linux/completion.h>

struct completion my_completion;

init_completion(&my_completion);

void wait_for_completion(struct completion *c);

void complete(struct completion *c);

void complete_all(struct completion *c);
```

# Spainlocks

Note that all spinlock waits are,by their nature,uninterruptible.Once you call spin_lock,you will spin until the lock becomes available.

```c
#include <linux/spinlock.h>

spinlock_t my_lock = SPIN_LOCK_UNLOCKED;//init

void spin_lock_init(spinlock_t *lock); 

void spin_lock(spinlock_t *lock);// disable kernel preemption
void spin_lock_irqsave(spinlock_t *lock,unsigned long flags)
void spin_lock_irq(spinlock_t *lock);
void spin_lock_bh(spinlock_t *lock);

void spin_unlock(spinlock_t *lock);
```

#### Reader/Writer Spainlocks

# Locking Traps

#### Ambiguous Rules

to make you locking work properly,you have to write some functions with the assumption that their caller has already acquired the relevant lock

#### Lock Ordering Rules

when multiple locks must be acquired,they should always be acquired in the same order

A couple of rules of thumb can help. If you must obtain a lock that is local to your code (a device lock, say) along with a lock belonging to a more central part of the kernel, take your lock first. If you have a combination of semaphores and spinlocks,you must, of course, obtain the semaphore(s) first; calling down (which can sleep) while holding a spinlockis a serious error. But most of all, try to avoid situations where you need more than one lock.

#### Fine- Versus Coarse- Grained Locking

大粒度的锁会造成系统很大的性能下降（比如 big kernel lock）,而小粒度的锁，会造成更多的bug，则两者之间，需要一个权衡

# Alternatives to Locking

#### Lock-Free Algorithms

Circular buffers :The producer is the only thread that is allowed to modify the write index and the array location it points to,The reader, in turn, is the only thread that can access the read index and the value it points to

#### Atomic Variables

The kernel provides an atomic integer type called atomic_t,defined in asm/atomic

#### Bit Operations

asm/bitops.h

# seqlocks

