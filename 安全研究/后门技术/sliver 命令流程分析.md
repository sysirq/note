client --> console --> console.go:

```go
type SliverConsoleClient struct {
	App                      *console.Console
	Rpc                      rpcpb.TeamServerRPCClient
	ActiveTarget             *ActiveTarget
	EventListeners           *sync.Map
	BeaconTaskCallbacks      map[string]BeaconTaskCallback
	BeaconTaskCallbacksMutex *sync.Mutex
	Settings                 *assets.ClientSettings
	IsServer                 bool
	IsCLI                    bool
	jsonHandler              slog.Handler
	printf                   func(format string, args ...any) (int, error)
}
.......
// NewConsole creates the sliver client (and console), creating menus and prompts.
// The returned console does neither have commands nor a working RPC connection yet,
// thus has not started monitoring any server events, or started the application.
func NewConsole(isServer bool) *SliverConsoleClient {
.........................
}
```

客户端命令注册位置：

client/cli/cli.go:init() -> client/cli/implant.go:implantCmd() --> client/command/sliver.go:SliverCommands()

服务端命令组册位置：

server/start.go:Start() -> server/console/console.go:Start()