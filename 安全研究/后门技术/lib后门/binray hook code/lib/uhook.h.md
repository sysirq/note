```c
#ifndef __MY_UHOOK_H__
#define __MY_UHOOK_H__

typedef struct {
	void			*handler_addr;		// handler fn address
	int 		is_used;		//是否被使用
	const char	*name;		//name
	void		*func_addr;		// func orignal addr
	
	unsigned char 		func_code[100];//func orignal nbytes of code
	unsigned char 		trampoline_code[100];

	unsigned long		nbytes;		// orignal fn nbytes inst has changed
} uhook_t;

int uhook_init();
uhook_t *find_uhook(char *func_name);
int uhook(char *func_name,unsigned long func_start_addr,unsigned long func_end_addr,void *handle_addr);
int temp_close_hook(uhook_t *hook);
int enable_temp_close_hook(uhook_t *hook);
#endif
```