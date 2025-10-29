# Zyxel-gui/httpd.conf

- 5.37 vs 5.38 未变化
- 5.38 vs 5.39 变化

```
< <Directory "/usr/local/zyxel-gui/htdocs/ztp/cgi-bin">
< 	<IfModule mod_rewrite.c>
< 		Options ExecCGI FollowSymLinks
< 		AllowOverride None
< 		RewriteRule ^([^\.]+)/?$ $1.py [L]
<  	</IfModule>
< </Directory>
```