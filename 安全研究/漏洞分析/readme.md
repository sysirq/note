# Nuclei

### 代理使用


```
-p, -proxy string[]        list of http/socks5 proxy to use (comma separated or file input)
```

eg:

```
nuclei -l xxx.txt -t xxx.yaml -p http://192.168.1.1:8080
```


### 与shodan的联动

```
export SHODAN_API_KEY=xxx
nuclei -id 'CVE-2021-26855' -uq 'vuln:CVE-2021-26855' -ue shodan
```

### 与fofa的联动

```
export FOFA_EMAIL=xxx
export FOFA_KEY=xxx
```

### 有用的命令

```
nuclei -id CVE-2024-8877 -stats -uc -ul 3000 -ue shodan -p socks5://127.0.0.1:1080
```

# 资料

Running Nuclei

https://docs.projectdiscovery.io/tools/nuclei/running#scan-on-internet-database

nuclei模板编写总结

https://www.cnblogs.com/backlion/p/18326684

学习笔记-nuclei

https://www.cnblogs.com/haidragon/p/16852363.html

Introduction to Nuclei Templates

https://docs.projectdiscovery.io/templates/introduction

Basic HTTP Protocol

https://docs.projectdiscovery.io/templates/protocols/http/basic-http

nuclei中文readme

https://github.com/projectdiscovery/nuclei/blob/dev/README_CN.md