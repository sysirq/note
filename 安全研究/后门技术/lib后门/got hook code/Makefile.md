```makefile
all:
	gcc -fPIC -pie -DDEBUG main.c -o main -ldl
clean:
	rm -rf main
```

