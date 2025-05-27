# 函数

- `cJSON *cJSON_Parse(const char *json_string);`:将JSON 格式的字符串解析为 `cJSON` 结构体树的核心函数

```
成功：返回一个指向 cJSON 对象（即 JSON 结构树）的指针。
失败：返回 NULL，说明解析失败。
````

注意事项:
```
返回的 cJSON * 对象必须使用 cJSON_Delete() 释放，否则会导致内存泄漏。
如果解析失败，可以通过 cJSON_GetErrorPtr() 获取出错位置。
```

Eg:

```c
#include <stdio.h>
#include <stdlib.h>
#include "cJSON.h"

int main() {
    const char *json_text = "{\"name\":\"Alice\",\"age\":30,\"admin\":true}";

    cJSON *root = cJSON_Parse(json_text);
    if (root == NULL) {
        const char *error_ptr = cJSON_GetErrorPtr();
        if (error_ptr != NULL) {
            fprintf(stderr, "JSON 解析错误：在位置 %ld 附近\n", error_ptr - json_text);
        }
        return EXIT_FAILURE;
    }

    // 提取字段
    cJSON *name = cJSON_GetObjectItem(root, "name");
    cJSON *age = cJSON_GetObjectItem(root, "age");
    cJSON *admin = cJSON_GetObjectItem(root, "admin");

    printf("Name: %s\n", cJSON_IsString(name) ? name->valuestring : "NULL");
    printf("Age: %d\n", cJSON_IsNumber(age) ? age->valueint : -1);
    printf("Admin: %s\n", cJSON_IsBool(admin) && admin->valueint ? "true" : "false");

    // 释放资源
    cJSON_Delete(root);
    return 0;
}
```

错误调试

```c
cJSON *root = cJSON_Parse(json);
if (!root) {
    printf("Parse Error: %s\n", cJSON_GetErrorPtr());
}
```

- 类型判断

```c
cJSON_IsNull(item); //是否为 null
cJSON_IsBool(item); //是否为布尔（true 或 false）
cJSON_IsTrue(item); //是否为 true
cJSON_IsFalse(item); //是否为 false
cJSON_IsNumber(item); //是否为数字
cJSON_IsString(item); //是否为字符串
cJSON_IsArray(item); //是否为数组
cJSON_IsObject(item); //是否为对象
cJSON_IsRaw(item); //是否为 raw（基本不常用）
```

- 对象字段提取

```c
cJSON *cJSON_GetObjectItem(const cJSON *object, const char *string);//不区分大小写
cJSON *cJSON_GetObjectItemCaseSensitive(const cJSON *object, const char *string);//区分大小写
```

Eg:

```c
// 提取字段
cJSON *name = cJSON_GetObjectItem(root, "name");
cJSON *age = cJSON_GetObjectItem(root, "age");
cJSON *admin = cJSON_GetObjectItem(root, "admin");

printf("Name: %s\n", cJSON_IsString(name) ? name->valuestring : "NULL");
printf("Age: %d\n", cJSON_IsNumber(age) ? age->valueint : -1);
printf("Admin: %s\n", cJSON_IsBool(admin) && admin->valueint ? "true" : "false");
```

- 数组提取

```c
cJSON_GetArrayItem(arr, index);//获取数组元素
```

- 数组遍历

```c
if (!cJSON_IsArray(tasks_json))
{
    DLX(0, printf("\tJSON tasks is not an array\n"));
    retcode = -1;
    goto end;
}
cJSON_ArrayForEach(task_json, tasks_json)
{
    cmd = cJSON_GetObjectItemCaseSensitive(task_json, "cmd");
    seq = cJSON_GetObjectItemCaseSensitive(task_json, "seq");

    if (!cJSON_IsString(cmd) || !cJSON_IsNumber(seq))
    {
        DLX(0, printf("\tGet task type error\n"));
        retcode = -1;
        goto end;
    }

    DLX(0, printf("\tcmd: %s , seq: %d\n", cmd->valuestring, seq->valueint));

    handle_func = handler_function_lookup(cmd->valuestring);
    if (handle_func == NULL)
    {
        DLX(0, printf("\tnot found %s handler\n", cmd->valuestring));
        continue;
    }
    retcode = handle_func(beacon, task_json);
}
```

- json对象创建

```c
task_response = cJSON_CreateObject();
cJSON_AddStringToObject(task_response, "cmd", "ls");
cJSON_AddStringToObject(task_response, "result", result);
cJSON_AddStringToObject(task_response, "data", data);
cJSON_AddNumberToObject(task_response, "seq", seq->valueint);
cJSON_AddItemToArray(beaconInfo->tasks_response, task_response);
cJSON_Delete(beacon->tasks_response);
```

- json对象复制

```c
cJSON *cJSON_Duplicate(const cJSON *item, const cJSON_bool recurse);
item：需要复制的 cJSON 对象。
recurse：是否递归复制子项，通常传入 true 来复制所有子项，或者传入 false 仅复制顶层数据。
```