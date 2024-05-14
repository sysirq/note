# 64位汇编
当参数少于7个时， 参数从左到右放入寄存器: rdi, rsi, rdx, rcx, r8, r9。

当参数为7个以上时， 前 6 个与前面一样， 但后面的依次从 “右向左” 放入栈中，即和32位汇编一样。

参数个数大于 7 个的时候

H(a, b, c, d, e, f, g, h);

a->%rdi, b->%rsi, c->%rdx, d->%rcx, e->%r8, f->%r9

h->8(%esp)

g->(%esp)

call H

# 国外逆向网站
https://0x00sec.org/

https://greysec.net/