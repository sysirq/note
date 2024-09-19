```sh
#/bin/bash
rm -rf main.*

nm --defined-only main | awk '{ if($2 == "T" || $2 == "t" || $2 == "B" || $2 == "b" || $2 == "D" || $2 == "d") print $3 }' > main.syms
objcopy --only-keep-debug main main.debug
objcopy -S --keep-symbols=main.syms main.debug main.mini_debuginfo

#cp main.mini_debuginfo gnu_debugdata

xz main.mini_debuginfo
objcopy -S main
objcopy --add-section .gnu_debugdata=main.mini_debuginfo.xz main

rm -rf main.*
```

