# 与IDA的配合

IDA所在机器上运行:

```
ida-pro-mcp --transport http://0.0.0.0:8744
```

启动IDA


修改gemini cli所在的配置文件即可使用(~/.gemini/settings.json 或者 项目目录下文件 .gemini/settings.json即可)：

```json
{
....................
  "mcpServers":{
    "idaMcpServer":{
      "url":"http://192.168.64.6:8744/sse"
    }
  }
}
```

# 参考资料

MCP servers with the Gemini CLI

https://geminicli.com/docs/tools/mcp-server/