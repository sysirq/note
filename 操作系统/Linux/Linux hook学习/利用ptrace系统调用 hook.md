```c
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include <sys/ptrace.h>
#include <sys/user.h>
#include <sys/wait.h>

void getdata(pid_t child,long addr,char *str,int len);
void setdata(pid_t child,long addr,char *str,int len);

int main(int argc,char *argv[])
{
	pid_t traced_process = 0;
	long ret = 0;
	struct user_regs_struct regs = {};
	struct user_regs_struct oldregs = {};
	long ins = 0;
	//char code[] = {0xcd,0x80,0xcc,0};//int 0x80,int 3
	char code[] = {0xeb,0x0e,0x68,0x65,0x6c,0x6c,0x6f,0x2c,0x77,0x6f,0x72,0x6c,0x64,0x21,0x0a,0x00,0xe8,0x00,0x00,0x00,0x00,0x41,0x5f,0x49,0x83,0xef,0x13,0xb8,0x01,0x00,0x00,0x00,0xbf,0x02,0x00,0x00,0x00,0x4c,0x89,0xfe,0xba,0x0e,0x00,0x00,0x00,0x0f,0x05,0xcd,0x80,0xcc};// print "hello world"
	int code_len = sizeof(code);
	char backup[sizeof(code)];
	
	if(argc != 2){
		printf("Usage:%s <pid to be traced>\n",argv[0]);
		exit(1);
	}
	
	traced_process = atoi(argv[1]);

	ret = ptrace(PTRACE_ATTACH,traced_process,NULL,NULL);
	if(ret == -1){
		perror("attach error\n");
		exit(1);
	}

	wait(NULL);
	
	ptrace(PTRACE_GETREGS,traced_process,NULL,&regs);
	oldregs = regs;

	getdata(traced_process,regs.rip,backup,code_len);
	setdata(traced_process,regs.rip,code,code_len);

	ptrace(PTRACE_CONT,traced_process,NULL,NULL);

	wait(NULL);

	printf("The process stopped,putting back the original instructions\n");
	printf("Press <enter> to continue\n");
	getchar();
	setdata(traced_process,oldregs.rip,backup,code_len);
	
	ptrace(PTRACE_SETREGS,traced_process,NULL,&oldregs);
	ptrace(PTRACE_DETACH,traced_process,NULL,NULL);
	return 0;
}

void getdata(pid_t child,long addr,char *str,int len)
{
	long data;
	int j = len / sizeof(data);
	int i;
	char *pos = str;
	
	for(i = 0;i<j;i++){
		data = ptrace(PTRACE_PEEKDATA,child,addr + i*sizeof(data),NULL);	
		memcpy(pos,&data,sizeof(data));
		pos += sizeof(data);
	}
	
	j = len %sizeof(data);
	if( j != 0){
		data = ptrace(PTRACE_PEEKDATA,child,addr + i*sizeof(data),NULL);	
		memcpy(pos,&data,j);
	}
}

void setdata(pid_t child,long addr,char *str,int len)
{
	long data;
	int i,j;
	j = len /sizeof(data);
	
	for(i = 0;i<j;i++){
		ptrace(PTRACE_POKEDATA,child,addr + i* sizeof(data),*(long*)(str+i*sizeof(data)));
	}

	j = len % sizeof(data);
	if(j!=0){
		data = ptrace(PTRACE_PEEKDATA,child,addr + i* sizeof(data),NULL);//align
		memcpy(&data,str+i*sizeof(data),j);
		ptrace(PTRACE_POKEDATA,child,addr + i* sizeof(data),data);
	}
}
```

# 参考质料：

https://www.linuxjournal.com/article/6100

https://www.linuxjournal.com/article/6210