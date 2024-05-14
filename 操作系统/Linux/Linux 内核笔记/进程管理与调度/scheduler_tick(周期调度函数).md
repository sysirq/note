scheduler_tick --> task_tick


task_tick --> task_tick_fair

task_tick_fair --> entity_tick:调用update_curr更新runtime和队列的min_vruntime，调用update_entity_load_avg计算负载贡献。调用 check_preempt_tick，判断是否切换到下一个进程

check_preempt_tick:


```c
static void
check_preempt_tick(struct cfs_rq *cfs_rq, struct sched_entity *curr)
{
	unsigned long ideal_runtime, delta_exec;
	struct sched_entity *se;
	s64 delta;

	ideal_runtime = sched_slice(cfs_rq, curr);
	delta_exec = curr->sum_exec_runtime - curr->prev_sum_exec_runtime;
	if (delta_exec > ideal_runtime) {//该调度实体运行的时间是否超过该调度实体在一个调度周期内获得的理想时间，如果超过则进行切换
		resched_curr(rq_of(cfs_rq));
		/*
		 * The current task ran long enough, ensure it doesn't get
		 * re-elected due to buddy favours.
		 */
		clear_buddies(cfs_rq, curr);
		return;
	}

	/*
	 * Ensure that a task that missed wakeup preemption by a
	 * narrow margin doesn't have to wait for a full slice.
	 * This also mitigates buddy induced latencies under load.
	 */
	if (delta_exec < sysctl_sched_min_granularity)//sysctl_sched_min_granularity为调度实体运行的最小时间
		return;

	se = __pick_first_entity(cfs_rq);
	delta = curr->vruntime - se->vruntime;

	if (delta < 0)//判断是否有调度实体的vruntime小于当前调度实体的vruntime
		return;

	if (delta > ideal_runtime)
		resched_curr(rq_of(cfs_rq));
}
```