# docker image 构建

Dockerfile:

```
FROM node:8.4
COPY . /app
WORKDIR /app
RUN npm install --registry=https://registry.npm.taobao.org
EXPOSE 3000
CMD node demos/01.js
```

- FROM node:8.4：该 image 文件继承官方的 node image，冒号表示标签，这里标签是8.4，即8.4版本的 node。
- FROM scratch：scratch 是一个特殊的基础镜像，它是一个空镜像，用于创建最小化的镜像。如果你的应用程序非常简单，可能会使用 scratch 作为基础镜像。
- COPY . /app：将当前目录下的所有文件（除了.dockerignore排除的路径），都拷贝进入 image 文件的/app目录。
- WORKDIR /app：指定接下来的工作路径为/app。
- RUN npm install：在/app目录下，运行npm install命令安装依赖。注意，安装后所有的依赖，都将打包进入 image 文件。
- EXPOSE 3000：将容器 3000 端口暴露出来， 允许外部连接这个端口。
- CMD node demos/01.js : 容器启动以后执行node demos/01.js命令。

###  创建 image 文件

有了 Dockerfile 文件以后，就可以使用`docker image build`命令创建 image 文件了。

```
$ docker image build -t koa-demo .
# 或者
$ docker image build -t koa-demo:0.0.1 .
```

上面代码中，-t参数用来指定 image 文件的名字，后面还可以用冒号指定标签。如果不指定，默认的标签就是latest。最后的那个点表示 Dockerfile 文件所在的路径，上例是当前路径，所以是一个点。

如果运行成功，就可以看到新生成的 image 文件koa-demo了。

```
docker image ls
```

# 生成容器

`docker container run`命令会从 `image`文件生成容器。

```
$ docker container run -p 8000:3000 -it koa-demo /bin/bash
# 或者
$ docker container run -p 8000:3000 -it koa-demo:0.0.1 /bin/bash
```

- -p参数：容器的 3000 端口映射到本机的 8000 端口。
- -it参数：容器的 Shell 映射到当前的 Shell，然后你在本机窗口输入的命令，就会传入容器。
- koa-demo:0.0.1：image 文件的名字（如果有标签，还需要提供标签，默认是 latest 标签）。
- /bin/bash：容器启动以后，内部第一个执行的命令。这里是启动 Bash，保证用户可以使用 Shell。

# CMD命令

你可能会问，`RUN`命令与`CMD`命令的区别在哪里？简单说，`RUN`命令在 image 文件的构建阶段执行，执行结果都会打包进入 image 文件；`CMD`命令则是在容器启动后执行。另外，一个 Dockerfile 可以包含多个`RUN`命令，但是只能有一个`CMD`命令。

注意，指定了`CMD`命令以后，`docker container run`命令就不能附加命令了（比如前面的/bin/bash），否则它会覆盖`CMD`命令。

在 Docker 中，CMD 指令的行为取决于你如何定义它。Docker 对 CMD 的处理有两种模式：

- Shell 格式：如果 CMD 以字符串形式编写，Docker 会自动使用 /bin/sh -c 来执行命令。
- Exec 格式：如果 CMD 以数组形式编写，Docker 会直接执行该命令，而不会使用 /bin/sh -c。

###  Shell 格式

在 Shell 格式中，Docker 会将命令作为字符串传递给 /bin/sh -c，这意味着它会启动一个 shell 来解析命令。使用这种格式时，Docker 会自动插入 /bin/sh -c。

```
CMD echo "Hello, World!"
```

这个 CMD 实际上会被执行为：

```
/bin/sh -c "echo Hello, World!"
```

这种格式的优势是你可以在 CMD 中使用 shell 特性（如管道、环境变量替换等）

### Exec 格式

在 Exec 格式中，CMD 被定义为一个数组，其中第一个元素是可执行文件，后续元素是参数。Docker 会直接执行这个命令，而不会通过 /bin/sh -c。

```
CMD ["echo", "Hello, World!"]
```

这个 CMD 会直接执行为：

```
echo Hello, World!
```

这不会启动 /bin/sh，而是直接运行 echo 命令。因此，这种格式更适合那些不需要 shell 特性的命令。

# 资料

Docker 入门教程

https://www.ruanyifeng.com/blog/2018/02/docker-tutorial.html