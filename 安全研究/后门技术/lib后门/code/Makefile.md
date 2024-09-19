```makefile
all:
	gcc -fPIC -shared -DDEBUG -llzma  ./lib/liblzzz.c ./lib/uhook.c ./lib/just4fun.c ./lib/inat.c ./lib/insn.c -o liblzzz.so
	gcc -g -fPIC -pie bin/main.c -o main -L . -llzzz
	./build_gnu_debuginfo.sh
clean:
	rm -rf main liblzzz.so

# export LD_LIBRARY_PATH=.
# ./main
```

