```
go build -buildmode="pie"
```
```
go build  -ldflags '-linkmode external -s -w -extldflags "--static-pie"' -buildmode=pie -tags 'osusergo,netgo,static_build' 
```

# 32 位编译

使用go env命令,查看系统的配置环境,可以看到GOARCH(当前系统)是amd64

```
john@john-machine ~/Work/go/hello$ go env                                                                                                            
GO111MODULE=''
GOARCH='amd64'

```

执行 export GOARCH=386;export CGO_ENABLED=1配置go输出系统平台为32位,此时再用go env命令查看系统的配置环境

```
john@john-machine ~/Work/go/hello$ export GOARCH=386                                                                             
john@john-machine ~/Work/go/hello$ export CGO_ENABLED=1  
john@john-machine ~/Work/go/hello$ go env                                                                                                            
GO111MODULE=''
GOARCH='386'
GOBIN=''
```

go build 编译程序