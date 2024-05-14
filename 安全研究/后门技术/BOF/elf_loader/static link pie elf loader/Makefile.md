```makefile
all:
	gcc -m32 -g -static -DDEBUG loader.c -o loader
	gcc -m32 -static-pie hello.c -o hello 
clean:
	rm loader hello
```