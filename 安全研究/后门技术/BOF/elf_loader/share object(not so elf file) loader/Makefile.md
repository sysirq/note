```makefile
all:
	gcc -DDEBUG loader.c -fpie -o loader
	gcc -c -fPIC hello.c -o hello 
clean:
	rm loader hello
```

