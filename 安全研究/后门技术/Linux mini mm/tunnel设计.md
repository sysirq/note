# 数据结构

选择 fifo

```c
static struct tunnel_data* tunnel_data_create(void)
{
    struct tunnel_data *tunnel_data = malloc(sizeof(struct tunnel_data));
    if(tunnel_data == NULL ) return NULL;

    tunnel_data->addr_rd = 0;
    tunnel_data->addr_wr = 0;
    tunnel_data->length = TUNNEL_DATA_MAX_SIZE;

    return tunnel_data;
}

static int tunnel_data_isEmpty(struct tunnel_data *tunnel_data)
{
    return (tunnel_data->addr_wr == tunnel_data->addr_rd);
}

int tunnel_data_isFull(struct tunnel_data *tunnel_data)
{
    return ((tunnel_data->addr_wr + 1) % tunnel_data->length == tunnel_data->addr_rd);
}

int tunnel_data_count(struct tunnel_data *tunnel_data)
{
    if(tunnel_data->addr_rd <= tunnel_data->addr_wr)
        return (tunnel_data->addr_wr - tunnel_data->addr_rd);
    //addr_rd > addr_wr;
    return (tunnel_data->length + tunnel_data->addr_wr - tunnel_data->addr_rd);
}

int tunnel_data_write(struct tunnel_data *tunnel_data, char data)
{
    if(tunnel_data_isFull(tunnel_data)){
        return -1;
    }
    
    tunnel_data->fifo[tunnel_data->addr_wr] = data;
    tunnel_data->addr_wr = (tunnel_data->addr_wr + 1) % tunnel_data->length;

    return 0;
}

int tunnel_data_read(struct tunnel_data *tunnel_data,char *data)
{

    if(tunnel_data_isEmpty(tunnel_data)){
        return -1;
    }
    
    *data = tunnel_data->fifo[tunnel_data->addr_rd];
    tunnel_data->addr_rd = (tunnel_data->addr_rd + 1) % tunnel_data->length;

    return 0;
}
```

# 数据同步方式

首先操作tunnel情况有：

*   木马收到客户端发来的tunnel数据包，需要写入到指定的tunnel中
*   模块会调用注册、卸载、读写tunnel 函数

如何保证他们之间的同步问题？
