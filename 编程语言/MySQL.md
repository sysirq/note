# root 密码配置

执行 mysql\_secure\_installation 命令设置root密码与一些安全设置

# 创建用户

```sql
CREATE USER 'username'@'host' IDENTIFIED BY 'password';
```

*   username：你将创建的用户名
*   host：指定该用户在哪个主机上可以登陆，如果是本地用户可用localhost，如果想让该用户可以从任意远程主机登陆，可以使用通配符%
*   password：该用户的登陆密码，密码可以为空，如果为空则该用户可以不需要密码登陆服务器

# 数据库创建

# 授权

```sql
GRANT privileges ON databasename.tablename TO 'username'@'host'
```

*   privileges：用户的操作权限，如SELECT，INSERT，UPDATE等，如果要授予所的权限则使用ALL
*   databasename：数据库名
*   tablename：表名，如果要授予该用户对所有数据库和表的相应操作权限则可用*表示，如*.\*

# 删除用户

```sql
DROP USER 'username'@'host';
```

