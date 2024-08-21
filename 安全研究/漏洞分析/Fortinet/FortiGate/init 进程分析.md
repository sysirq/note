```c
__int64 __fastcall main(signed int a1, const char **a2, char **a3)
{
  const char *v5; // rax
  bool v6; // dl
  bool v7; // cf
  bool v8; // zf
  const char *v9; // rsi
  __int64 v10; // rcx
  const char *v11; // rdi
  int v12; // eax
  int v13; // r12d
  const char *v14; // rax
  __int64 v15; // rdi
  const char *v16; // rsi
  const char *v18; // [rsp-8h] [rbp-58h]
  struct timespec requested_time; // [rsp+0h] [rbp-50h] BYREF
  char *argv[8]; // [rsp+10h] [rbp-40h] BYREF

  argv[3] = (char *)__readfsqword(0x28u);
  sub_4554E0("main", 2635);
  sub_450F70();
  nullsub_95648();
  sub_450FE0(a2);
  if ( a1 > 1 && !strcmp(a2[1], "return99") )
    exit(99);
  sub_18A1160();
  qword_4884678 = 0LL;
  qword_4884690 = (__int64)sub_452F30;
  qword_48846B8 = 0LL;
  qword_4884700 = qword_BFB9AE0 + 100;
  qword_48846D0 = (__int64)sub_452F70;
  qword_48846F8 = 0LL;
  qword_4884710 = (__int64)sub_4519E0;
  sub_18A11A0(&unk_48846E0);
  qword_4884738 = 0LL;
  qword_4884750 = (__int64)sub_453450;
  qword_4884748 = 0LL;
  sub_18A1260(&unk_4884720, qword_BFB9AE0 + 6000);
  v5 = *a2;
  v6 = strcmp(*a2, "/bin/init") != 0;
  v7 = 0;
  v8 = !v6;
  if ( !v6 )
  {
    argv[0] = "/bin/initXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX";
    argv[1] = 0LL;
    execve("/bin/initXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX", argv, 0LL);
    v5 = *a2;
  }
  v9 = v5;
  v10 = 9LL;
  v11 = "/bin/init";
  do
  {
    if ( !v10 )
      break;
    v7 = *v9 < (unsigned int)*v11;
    v8 = *v9++ == *v11++;
    --v10;
  }
  while ( v8 );
  if ( (!v7 && !v8) != v7 )
    return sub_44C140(a1, a2);
...............
```

对于第一次执行 /bin/init 会 execve("/bin/initXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX", argv, 0LL);

然后在：

```
  v9 = v5;
  v10 = 9LL;
  v11 = "/bin/init";
  do
  {
    if ( !v10 )
      break;
    v7 = *v9 < (unsigned int)*v11;
    v8 = *v9++ == *v11++;
    --v10;
  }
  while ( v8 );
  if ( (!v7 && !v8) != v7 )
    return sub_44C140(a1, a2);
```

这里判断argv[0]的前9个字节是不是/bin/init，如果是则不执行sub_44C140，继续执行main函数的后面初始化部分，不是则执行。

对于argv[0]为/bin/sslvpnd，则执行sub_44C140：

```c
__int64 __fastcall sub_44C140(unsigned int a1, const char **a2)
{
  char **v4; // rbx
  char *v5; // rax
  char *v6; // rax
  const char *v7; // rdi
  char *v8; // r12
  char *v9; // rsi
  int v11; // eax

  v4 = &s2;
  v5 = basename(*a2);
  v6 = strdup(v5);
  v7 = s2;
  v8 = v6;
  if ( s2 )
  {
    while ( v4[1] )
    {
      v9 = basename(v7);
      if ( !strcmp(v8, v9) )
      {
        free(v8);
        sub_29E3170();
        v11 = ((__int64 (__fastcall *)(_QWORD, const char **))v4[1])(a1, a2);
        exit(v11);
      }
      v7 = v4[2];
      v4 += 2;
      if ( !v7 )
      {
        sub_208C7E0((__int64)"%s: Could not find main function for %s\n", "fortiexec_call_main", *a2);
        goto LABEL_7;
      }
    }
  }
  sub_208C7E0((__int64)"%s: Could not find main function for %s\n", "fortiexec_call_main", *a2);
  if ( v8 )
LABEL_7:
    free(v8);
  return 0LL;
}
```

通过/bin/目录下的文件基本上都是软连接到/bin/init，以及该函数的分析，我们可以判断出，该函数通过argv[0]，找到对应的handler

用IDA Python提取之:

```python
import idaapi

def get_string(ea):
    i = 0;
    str = b''
    while idaapi.get_byte(ea+i) != 0:
        str += idaapi.get_byte(ea+i).to_bytes(1,byteorder = 'little')
        i = i + 1
    return str.decode()

handler_addr = 0x42A3A40 # sub_44C140 函数中的 s2

while True:
    handler_name_addr = idaapi.get_qword(handler_addr)
    if handler_name_addr == 0:
        break
    handler_func_addr = idaapi.get_qword(handler_addr+8)
    handler_name = get_string(handler_name_addr)
    print("handler name:",handler_name)
    print("handler func addr:",hex(handler_func_addr))
    handler_addr += 16
    
```

Output:

```
handler name: /bin/alarmd
handler func addr: 0x1196e60
handler name: /bin/alertmail
handler func addr: 0x462d80
handler name: /bin/acs-sdn-change
handler func addr: 0x20358e0
handler name: /bin/acs-sdn-update
handler func addr: 0x2035900
handler name: /bin/acs-sdn-status
handler func addr: 0x2035920
handler name: /bin/authd
handler func addr: 0x473720
handler name: /bin/foauthd
handler func addr: 0x473a10
handler name: /bin/fcnacd
handler func addr: 0xaaed00
handler name: /bin/fssod
handler func addr: 0xe388e0
handler name: /bin/clearpass
handler func addr: 0x896ce0
handler name: /bin/bgpd
handler func addr: 0x4f7b80
handler name: /bin/ripd
handler func addr: 0x15c5100
handler name: /bin/ripngd
handler func addr: 0x15d6d80
handler name: /bin/ospfd
handler func addr: 0x135e860
handler name: /bin/ospf6d
handler func addr: 0x1304690
handler name: /bin/pdmd
handler func addr: 0x13bfb70
handler name: /bin/pimd
handler func addr: 0x1420a40
handler name: /bin/pim6d
handler func addr: 0x13eb440
handler name: /bin/isisd
handler func addr: 0x10de600
handler name: /bin/imi
handler func addr: 0x10371e0
handler name: /bin/nsm
handler func addr: 0x12b6bd0
handler name: /bin/zebos_launcher
handler func addr: 0x202b680
handler name: /bin/cmdbsvr
handler func addr: 0x2313ad0
handler name: /bin/ddnscd
handler func addr: 0x90f180
handler name: /bin/dhcpcd
handler func addr: 0x937a10
handler name: /bin/dhcpd
handler func addr: 0x94b0b0
handler name: /bin/dhcprd
handler func addr: 0x9655a0
handler name: /bin/forticldd
handler func addr: 0xc40e80
handler name: /bin/forticron
handler func addr: 0xc7a7d0
handler name: /bin/garpd
handler func addr: 0x295e5c0
handler name: /bin/getty
handler func addr: 0xe48e70
handler name: /bin/mingetty
handler func addr: 0x12af460
handler name: /bin/dnsproxy
handler func addr: 0x99b0d0
handler name: /bin/sflowd
handler func addr: 0x1647b70
handler name: /bin/hatalk
handler func addr: 0xea2d50
handler name: /bin/hasync
handler func addr: 0xe98210
handler name: /bin/harelay
handler func addr: 0xe4e850
handler name: /bin/hamonitord
handler func addr: 0xe4c0f0
handler name: /bin/sla_probe
handler func addr: 0x1662a60
handler name: /bin/lnkmtd
handler func addr: 0x1168070
handler name: /bin/lnkmt_passive
handler func addr: 0x11835c0
handler name: /bin/vwl
handler func addr: 0x19936d0
handler name: /bin/eap_proxy
handler func addr: 0x9c6880
handler name: /bin/eap_supp
handler func addr: 0x9e1e40
handler name: /bin/hotplugd
handler func addr: 0xeb39e0
handler name: /bin/httpclid
handler func addr: 0x1898e80
handler name: /bin/httpsd
handler func addr: 0xec9af0
handler name: /bin/ikecryptd
handler func addr: 0xf3d550
handler name: /bin/iked
handler func addr: 0x1029dc0
handler name: /bin/voipd
handler func addr: 0x19696f0
handler name: /bin/ipldbd
handler func addr: 0x10726d0
handler name: /bin/acd
handler func addr: 0x461c50
handler name: /bin/cid
handler func addr: 0x87e530
handler name: /bin/lldprx
handler func addr: 0x1141ad0
handler name: /bin/lldptx
handler func addr: 0x1153c30
handler name: /bin/tvc
handler func addr: 0x18bd340
handler name: /bin/ipsengine
handler func addr: 0x10c63b0
handler name: /bin/ipsmonitor
handler func addr: 0x10c7530
handler name: /bin/l2tpd
handler func addr: 0x1128b60
handler name: /bin/merged_daemons
handler func addr: 0x1197190
handler name: /bin/fnbamd
handler func addr: 0xc1a460
handler name: /bin/syslogd
handler func addr: 0x18918c0
handler name: /bin/locallogd
handler func addr: 0x1193a90
handler name: /bin/fgtlogd
handler func addr: 0xb16e00
handler name: /bin/vpd
handler func addr: 0x197ef50
handler name: /bin/fclicense
handler func addr: 0xaa44f0
handler name: /bin/miglogd
handler func addr: 0x120ad00
handler name: /bin/kmiglogd
handler func addr: 0x11e29c0
handler name: /bin/newcli
handler func addr: 0x226a880
handler name: /bin/ntpd
handler func addr: 0x12f0060
handler name: /bin/ptpd
handler func addr: 0x15282d0
handler name: /bin/pppd
handler func addr: 0x1473270
handler name: /bin/pppoed
handler func addr: 0x148e840
handler name: /bin/pptpd
handler func addr: 0x1498960
handler name: /bin/pptpcd
handler func addr: 0x14939d0
handler name: /bin/proxyd
handler func addr: 0x14a56c0
handler name: /bin/quard
handler func addr: 0x154bfc0
handler name: /bin/gtpgkd
handler func addr: 0xe4b2a0
handler name: /bin/radiusd
handler func addr: 0x15641b0
handler name: /bin/radvd
handler func addr: 0x156fb90
handler name: /bin/scanunitd
handler func addr: 0x15ee8d0
handler name: /bin/sdncd
handler func addr: 0x1611af0
handler name: /bin/smit
handler func addr: 0x459440
handler name: /bin/snifferd
handler func addr: 0x1667490
handler name: /bin/httpsnifferd
handler func addr: 0x1667490
handler name: /bin/snmpd
handler func addr: 0x166d8f0
handler name: /bin/sshd
handler func addr: 0x16ea7e0
handler name: /bin/ssh-keygen
handler func addr: 0x170feb0
handler name: /bin/ssh
handler func addr: 0x16d0fd0
handler name: /bin/scp
handler func addr: 0x1711770
handler name: /bin/sslvpnd
handler func addr: 0x1858b00
handler name: /bin/telnetd
handler func addr: 0x1898e80
handler name: /bin/awsd
handler func addr: 0x4dafb0
handler name: /bin/ocid
handler func addr: 0x12faec0
handler name: /bin/openstackd
handler func addr: 0x1301070
handler name: /bin/sdnd
handler func addr: 0x1623d90
handler name: /bin/tftp
handler func addr: 0x264baf0
handler name: /bin/updated
handler func addr: 0x18bd680
handler name: /bin/uploadd
handler func addr: 0x18e0ef0
handler name: /bin/urlfilter
handler func addr: 0x18fe810
handler name: /bin/wf_monitor
handler func addr: 0x1909a00
handler name: /bin/ovrd
handler func addr: 0x13bf510
handler name: /bin/iotd
handler func addr: 0x2990b40
handler name: /bin/sessionsync
handler func addr: 0x1635320
handler name: /bin/fgfmd
handler func addr: 0xaefc50
handler name: /bin/wccpd
handler func addr: 0x1eed890
handler name: /bin/cw_acd
handler func addr: 0x724c80
handler name: /bin/cw_acd_helper
handler func addr: 0x7b3810
handler name: /bin/wpad_ac
handler func addr: 0x1f1e260
handler name: /bin/wlac
handler func addr: 0x810a50
handler name: /bin/wlac_hlp
handler func addr: 0x810a50
handler name: /bin/fortilinkd
handler func addr: 0xcb3e80
handler name: /bin/cu_acd
handler func addr: 0x5946f0
handler name: /bin/flcfgd
handler func addr: 0xb29f30
handler name: /bin/flpold
handler func addr: 0xbb39b0
handler name: /bin/dlpfingerprint
handler func addr: 0x97fb10
handler name: /bin/dlpfpcache
handler func addr: 0x982ee0
handler name: /bin/cwb
handler func addr: 0x810a50
handler name: /bin/wad
handler func addr: 0x1dd9dc0
handler name: /bin/wad_csvc_cs
handler func addr: 0x1dd9dc0
handler name: /bin/wad_csvc_db
handler func addr: 0x1dd9dc0
handler name: /bin/wa_dbd
handler func addr: 0x1f0de80
handler name: /bin/wa_cs
handler func addr: 0x1ef5f30
handler name: /bin/wad_usrinfohistory
handler func addr: 0x1e0e050
handler name: /bin/reportd
handler func addr: 0x159b960
handler name: /bin/vrrpd
handler func addr: 0x19892e0
handler name: /bin/bfdd
handler func addr: 0x4f7850
handler name: /bin/dhcp6s
handler func addr: 0x92a4b0
handler name: /bin/dhcp6r
handler func addr: 0x924d80
handler name: /bin/dhcp6c
handler func addr: 0x91d870
handler name: /bin/fsd
handler func addr: 0x291bfa0
handler name: /bin/extenderd
handler func addr: 0xa50b90
handler name: /bin/fips_self_test
handler func addr: 0xb251c0
handler name: /bin/mrd
handler func addr: 0x12b15e0
handler name: /bin/azd
handler func addr: 0x4e4760
handler name: /bin/netxd
handler func addr: 0x12b68c0
handler name: /bin/cloudinitd
handler func addr: 0x899120
handler name: /bin/gcpd
handler func addr: 0xe45210
handler name: /bin/radius-das
handler func addr: 0x8ff4f0
handler name: /bin/csfd
handler func addr: 0x8a58b0
handler name: /bin/fsvrd
handler func addr: 0xe3e0b0
handler name: /bin/ftm2
handler func addr: 0xe42680
handler name: /bin/autod
handler func addr: 0x4c6d30
handler name: /bin/kubed
handler func addr: 0x111fe50
handler name: /bin/fas
handler func addr: 0xaa3490
handler name: /bin/fsso_ldap
handler func addr: 0x4be1c0
handler name: /bin/sepmd
handler func addr: 0x162dac0
handler name: /bin/ipamd
handler func addr: 0x105e450
handler name: /bin/vned
handler func addr: 0x190e920
handler name: /bin/dpdk_early_init
handler func addr: 0x21a0e50
handler name: /bin/sfupgraded
handler func addr: 0x164f880
handler name: /bin/fds_notify
handler func addr: 0xad4950
handler name: /bin/speedtestd
handler func addr: 0x1688240
handler name: /bin/ipamsd
handler func addr: 0x1069dc0
```

