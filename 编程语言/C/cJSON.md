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

