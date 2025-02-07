# apache 模块注册

```c
#ifndef MODULE_MAGIC_NUMBER_MAJOR
#define MODULE_MAGIC_NUMBER_MAJOR 20120211
#endif
#define MODULE_MAGIC_NUMBER_MINOR 88                  /* 0...n */

/** Use this in all standard modules */
#define STANDARD20_MODULE_STUFF MODULE_MAGIC_NUMBER_MAJOR, \
                                MODULE_MAGIC_NUMBER_MINOR, \
                                -1, \
                                __FILE__, \
                                NULL, \
                                NULL, \
                                MODULE_MAGIC_COOKIE, \
                                NULL      /* rewrite args spot */
                                
AP_DECLARE_MODULE(http) = {
    STANDARD20_MODULE_STUFF,
    NULL,              /* create per-directory config structure */
    NULL,              /* merge per-directory config structures */
    NULL,              /* create per-server config structure */
    NULL,              /* merge per-server config structures */
    http_cmds,         /* command apr_table_t */
    register_hooks     /* register hooks */
};

typedef struct module_struct module;
struct module_struct {
    /** API version, *not* module version; check that module is
     * compatible with this version of the server.
     */
    int version;
    /** API minor version. Provides API feature milestones. Not checked
     *  during module init */
    int minor_version;
    /** Index to this modules structures in config vectors.  */
    int module_index;

    /** The name of the module's C file */
    const char *name;
    /** The handle for the DSO.  Internal use only */
    void *dynamic_load_handle;

    /** A pointer to the next module in the list
     *  @var module_struct *next
     */
    struct module_struct *next;

    /** Magic Cookie to identify a module structure;  It's mainly
     *  important for the DSO facility (see also mod_so).  */
    unsigned long magic;

    /** Function to allow MPMs to re-write command line arguments.  This
     *  hook is only available to MPMs.
     *  @param The process that the server is running in.
     */
    void (*rewrite_args) (process_rec *process);
    /** Function to allow all modules to create per directory configuration
     *  structures.
     *  @param p The pool to use for all allocations.
     *  @param dir The directory currently being processed.
     *  @return The per-directory structure created
     */
    void *(*create_dir_config) (apr_pool_t *p, char *dir);
    /** Function to allow all modules to merge the per directory configuration
     *  structures for two directories.
     *  @param p The pool to use for all allocations.
     *  @param base_conf The directory structure created for the parent directory.
     *  @param new_conf The directory structure currently being processed.
     *  @return The new per-directory structure created
     */
    void *(*merge_dir_config) (apr_pool_t *p, void *base_conf, void *new_conf);
    /** Function to allow all modules to create per server configuration
     *  structures.
     *  @param p The pool to use for all allocations.
     *  @param s The server currently being processed.
     *  @return The per-server structure created
     */
    void *(*create_server_config) (apr_pool_t *p, server_rec *s);
    /** Function to allow all modules to merge the per server configuration
     *  structures for two servers.
     *  @param p The pool to use for all allocations.
     *  @param base_conf The directory structure created for the parent directory.
     *  @param new_conf The directory structure currently being processed.
     *  @return The new per-directory structure created
     */
    void *(*merge_server_config) (apr_pool_t *p, void *base_conf,
                                  void *new_conf);

    /** A command_rec table that describes all of the directives this module
     * defines. */
    const command_rec *cmds;

    /** A hook to allow modules to hook other points in the request processing.
     *  In this function, modules should call the ap_hook_*() functions to
     *  register an interest in a specific step in processing the current
     *  request.
     *  @param p the pool to use for all allocations
     */
    void (*register_hooks) (apr_pool_t *p);

    /** A bitmask of AP_MODULE_FLAG_* */
    int flags;
};
```

通过逆向FGT，我们可以知道FGT中使用的Apache版本。然后通过git check到apache的特定版本，我们可以知道MODULE_MAGIC_NUMBER_MAJOR 与MODULE_MAGIC_NUMBER_MINOR的具体值。

通过IDA脚本，我们可以找到FGT中所有module

```python
import idc
import idaapi
import idautils

def get_string_at(ea):
    i = 0
    byte_array = bytearray()
    while True:
        b = idaapi.get_byte(ea+i)
        if b == 0:
            break
        byte_array.append(b)
        i = i + 1
    
    if i == 0:
        return ""
    return byte_array.decode('utf-8')
 

def find_all_sequences(data, sequence):
    sequence_length = len(sequence)
    data_length = len(data)
    indices = []
    
    position = 0
    
    while position < data_length:
        position = data.find(sequence, position)
        if position == -1:
            break
        indices.append(position)
        position += 1
    return indices

start_addr = 0x0000000000400000
end_addr   = 0x000000000F4D2EC8

number_major = 20120211
number_minor = 88

number_major_bytes = number_major.to_bytes(4, byteorder='little', signed=False)
number_minor_bytes = number_minor.to_bytes(4, byteorder='little', signed=False)

search_bytes = number_major_bytes + number_minor_bytes

img_data = idaapi.get_bytes(start_addr, end_addr - start_addr)
address = find_all_sequences(img_data,search_bytes)

for addr in address:
    addr += start_addr
    
    module_name_addr_addr = addr + 0x10
    module_name_addr = int.from_bytes(ida_bytes.get_bytes(module_name_addr_addr, 8),'little')
    module_name = get_string_at(module_name_addr)
    
    print("module addr: ",hex(addr))
    print("name: ",module_name)
    
    register_hooks_addr_addr = addr + 0x60
    register_hooks_addr = int.from_bytes(ida_bytes.get_bytes(register_hooks_addr_addr, 8),'little')
    print("register_hooks_addr: ",hex(register_hooks_addr))
```

对于FGT 7.2.0 输出为：

```log
module addr:  0x3f41e60
name:  /code/FortiOS/fortinet/fortiweb/modules/apache_module.c
register_hooks_addr:  0xc13360
module addr:  0x40e6e00
name:  /code/FortiOS/fortinet/apache2/server/core.c
register_hooks_addr:  0xdde970
module addr:  0x40e6ea0
name:  /code/FortiOS/fortinet/apache2/server/prefork.c
register_hooks_addr:  0xdec570
module addr:  0x40e71c0
name:  /code/FortiOS/fortinet/apache2/modules/http_core.c
register_hooks_addr:  0xe0f5d0
module addr:  0x40e7280
name:  /code/FortiOS/fortinet/apache2/modules/mod_headers.c
register_hooks_addr:  0xe19540
module addr:  0x40e7320
name:  /code/FortiOS/fortinet/apache2/modules/mod_mime.c
register_hooks_addr:  0xe1ac50
module addr:  0x40e73a0
name:  /code/FortiOS/fortinet/apache2/modules/mod_reqtimeout.c
register_hooks_addr:  0xe1bc40
module addr:  0x40e7440
name:  /code/FortiOS/fortinet/apache2/modules/mod_rewrite.c
register_hooks_addr:  0xe24b60
module addr:  0x40e74c0
name:  /code/FortiOS/fortinet/apache2/modules/mod_so.c
register_hooks_addr:  0xe257c0
module addr:  0x40e7540
name:  /code/FortiOS/fortinet/apache2/modules/mod_ssl.c
register_hooks_addr:  0xe261c0
```

通过

```
module addr:  0x3f41e60
name:  /code/FortiOS/fortinet/fortiweb/modules/apache_module.c
register_hooks_addr:  0xc13360
```

我们可以定位到FGT的所有CGI handler

```c
__int64 sub_C13360()
{
  sub_C13C50();
  return ap_hook_handler(sub_C13350, 0LL, 0LL, 10LL);
}

__int64 __fastcall sub_C13350(__int64 a1)
{
  return sub_C14B30(a1, &off_3F41C40);
}
```

```
.data:0000000003F41C40 off_3F41C40     dq offset aApiCmdbV2Handl
.data:0000000003F41C40                                         ; DATA XREF: sub_C13350↑o
.data:0000000003F41C40                                         ; "api_cmdb_v2-handler"
.data:0000000003F41C48                 dq offset sub_C58250
.data:0000000003F41C50                 dq offset aApiMonitorV2Ha ; "api_monitor_v2-handler"
.data:0000000003F41C58                 dq offset sub_C93930
.data:0000000003F41C60                 dq offset aApiLogHandler ; "api_log-handler"
.data:0000000003F41C68                 dq offset sub_C85F00
.data:0000000003F41C70                 dq offset aApiFmgHandler ; "api_fmg-handler"
.data:0000000003F41C78                 dq offset sub_C73530
.data:0000000003F41C80                 dq offset aApiFazHandler ; "api_faz-handler"
.data:0000000003F41C88                 dq offset sub_C6BC60
.data:0000000003F41C90                 dq offset aApiCsfHandler ; "api_csf-handler"
.data:0000000003F41C98                 dq offset sub_C97710
.data:0000000003F41CA0                 dq offset aApiHaHandler ; "api_ha-handler"
.data:0000000003F41CA8                 dq offset sub_C75540
.data:0000000003F41CB0                 dq offset aApiAuthenticat_0 ; "api_authentication-handler"
.data:0000000003F41CB8                 dq offset sub_C484F0
.data:0000000003F41CC0                 dq offset aSamlSpLoginHan_0+8 ; "login-handler"
.data:0000000003F41CC8                 dq offset sub_C30C60
.data:0000000003F41CD0                 dq offset aSamlSpLogoutHa_0+8 ; "logout-handler"
.data:0000000003F41CD8                 dq offset sub_C39920
.data:0000000003F41CE0                 dq offset aLogincheckHand_0 ; "logincheck-handler"
.data:0000000003F41CE8                 dq offset sub_C32D70
.data:0000000003F41CF0                 dq offset aFortiwebStatic_0 ; "fortiweb-static-handler"
.data:0000000003F41CF8                 dq offset sub_C29940
.data:0000000003F41D00                 dq offset aLoginpwdChange_0 ; "loginpwd_change-handler"
.data:0000000003F41D08                 dq offset sub_C38470
.data:0000000003F41D10                 dq offset aCheckPwdPolicy ; "check_pwd_policy-handler"
.data:0000000003F41D18                 dq offset sub_C381A0
.data:0000000003F41D20                 dq offset aSamlSpHandler_0 ; "saml-sp-handler"
.data:0000000003F41D28                 dq offset sub_C3F5A0
.data:0000000003F41D30                 dq offset aSamlSpLoginHan_0 ; "saml-sp-login-handler"
.data:0000000003F41D38                 dq offset sub_C3D1F0
.data:0000000003F41D40                 dq offset aSamlSpForticlo ; "saml-sp-forticloud-login-handler"
.data:0000000003F41D48                 dq offset sub_C3D200
.data:0000000003F41D50                 dq offset aSamlSpLogoutHa_0 ; "saml-sp-logout-handler"
.data:0000000003F41D58                 dq offset sub_C3E780
.data:0000000003F41D60                 dq offset aSamlSpLogoutPr_0 ; "saml-sp-logout-process-handler"
.data:0000000003F41D68                 dq offset sub_C3F580
.data:0000000003F41D70                 dq offset aSamlSpLogoutPr_1 ; "saml-sp-logout-process-forticloud-handl"...
.data:0000000003F41D78                 dq offset sub_C3F590
.data:0000000003F41D80                 dq offset aSamlIdpHandler_0 ; "saml-idp-handler"
.data:0000000003F41D88                 dq offset sub_C3F770
.data:0000000003F41D90                 dq offset aSamlIdpLoginCh_1 ; "saml-idp-login-check-handler"
.data:0000000003F41D98                 dq offset sub_C3FAB0
.data:0000000003F41DA0                 dq offset aSamlIdpLoginPr_1 ; "saml-idp-login-process-handler"
.data:0000000003F41DA8                 dq offset sub_C3FDF0
.data:0000000003F41DB0                 dq offset aSamlIdpLogoutP_1 ; "saml-idp-logout-process-handler"
.data:0000000003F41DB8                 dq offset sub_C40440
.data:0000000003F41DC0                 dq offset aRestrictedAcco ; "restricted-account-handler"
.data:0000000003F41DC8                 dq offset sub_C3B270
.data:0000000003F41DD0                 dq offset aApiReportsHand ; "api_reports-handler"
.data:0000000003F41DD8                 dq offset sub_C95280
.data:0000000003F41DE0                 dq offset aApiUsrbwlHandl ; "api_usrbwl-handler"
.data:0000000003F41DE8                 dq offset sub_C9E1D0
.data:0000000003F41DF0                 dq offset aApiUsrbwlqryHa ; "api_usrbwlqry-handler"
.data:0000000003F41DF8                 dq offset sub_C9EDB0
.data:0000000003F41E00                 dq offset aAdminSessionLi_3 ; "admin-session-limit-handler"
.data:0000000003F41E08                 dq offset sub_C12950
.data:0000000003F41E10                 dq offset aErrorHandler ; "error-handler"
.data:0000000003F41E18                 dq offset sub_C24E30
.data:0000000003F41E20                 dq offset aLogindisableHa ; "logindisable-handler"
.data:0000000003F41E28                 dq offset sub_C360C0
.data:0000000003F41E30                 dq offset aLogindisclaime_1 ; "logindisclaimer-handler"
.data:0000000003F41E38                 dq offset sub_C36AB0
.data:0000000003F41E40                 dq offset aAcmeOnlyHandle ; "acme-only-handler"
.data:0000000003F41E48                 dq offset sub_C11ED0
.data:0000000003F41E50                 align 20h
```

# FGT如何对URL请求进行处理呢？

