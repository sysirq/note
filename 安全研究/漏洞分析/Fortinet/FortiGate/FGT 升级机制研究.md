# 代码逆向分析

通过字符串：

```
.rodata:000000000235D348	00000059	C	Error : Boot image on disk: %s is corrupted, please try to update the firmware again !\n 
```

以及：

```
.rodata:0000000002B729DB	0000001B	C	Bad upgrade image. Abort.\n
```

我们可以快速定位到固件升级处理函数，以FGT 6.2.5 为例，该版本的固件升级函数为：

```c
__int64 __fastcall sub_438C10(char *name, char *a2, int a3, int a4)
{
  int v5; // edx
  int v6; // ecx
  int v7; // er8
  int v8; // er9
  FILE *v9; // r14
  __off_t v10; // r12
  _BYTE *v11; // rax
  int v12; // edx
  int v13; // ecx
  int v14; // er8
  int v15; // er9
  _BYTE *v16; // rbx
  int v17; // edx
  int v18; // ecx
  int v19; // er8
  int v20; // er9
  unsigned int v21; // er12
  int i; // er14
  int v23; // edi
  int v24; // edx
  int v25; // ecx
  int v26; // esi
  int v27; // er8
  int v28; // er9
  int v29; // er15
  int v30; // eax
  int v31; // er14
  int v32; // er12
  int v33; // eax
  int v34; // edx
  int v35; // ecx
  int v36; // er8
  int v37; // er9
  int v38; // edi
  int v39; // er12
  const char *v40; // rdi
  char *v41; // rax
  unsigned __int8 *v42; // rdi
  const unsigned __int16 *v43; // rdx
  unsigned __int8 *v44; // rcx
  __int64 v45; // r8
  char *v46; // r9
  char *v47; // rax
  char *v48; // rsi
  int v49; // edx
  int v50; // ecx
  int v51; // er8
  int v52; // er9
  int v54; // edx
  int v55; // ecx
  int v56; // er8
  int v57; // er9
  int v58; // edi
  int v59; // eax
  int v60; // er13
  int v61; // edx
  int v62; // ecx
  int v63; // er8
  int v64; // er9
  int v65; // edx
  int v66; // ecx
  int v67; // er8
  int v68; // er9
  int v69; // edx
  int v70; // ecx
  int v71; // er8
  int v72; // er9
  int v73; // edx
  int v74; // ecx
  int v75; // er8
  int v76; // er9
  int v77; // edx
  int v78; // ecx
  int v79; // er8
  int v80; // er9
  int v81; // edx
  int v82; // ecx
  int v83; // er8
  int v84; // er9
  const char *v85; // rdi
  int v86; // [rsp+8h] [rbp-608h]
  int v87; // [rsp+Ch] [rbp-604h]
  int v88; // [rsp+10h] [rbp-600h]
  unsigned int v89; // [rsp+14h] [rbp-5FCh]
  int v90; // [rsp+18h] [rbp-5F8h]
  int v91; // [rsp+18h] [rbp-5F8h]
  int v93; // [rsp+28h] [rbp-5E8h]
  _DWORD stat_loc[7]; // [rsp+3Ch] [rbp-5D4h] BYREF
  char *v96; // [rsp+58h] [rbp-5B8h]
  int v97; // [rsp+60h] [rbp-5B0h]
  int v98; // [rsp+68h] [rbp-5A8h]
  __int64 v99; // [rsp+80h] [rbp-590h]
  __int64 v100; // [rsp+88h] [rbp-588h]
  __int64 v101; // [rsp+90h] [rbp-580h]
  char *argv[6]; // [rsp+B0h] [rbp-560h] BYREF
  struct stat stat_buf; // [rsp+E0h] [rbp-530h] BYREF
  char v104; // [rsp+170h] [rbp-4A0h] BYREF
  _BYTE v105[7]; // [rsp+171h] [rbp-49Fh] BYREF
  char v106; // [rsp+18Fh] [rbp-481h] BYREF
  char s[64]; // [rsp+190h] [rbp-480h] BYREF
  char v108[512]; // [rsp+1D0h] [rbp-440h] BYREF
  char buf[520]; // [rsp+3D0h] [rbp-240h] BYREF
  unsigned __int64 v110; // [rsp+5D8h] [rbp-38h]

  v110 = __readfsqword(0x28u);
  if ( __xstat(1, name, &stat_buf) || (v9 = fopen(name, "r")) == 0LL )
  {
    sub_1930AC0((unsigned int)"Cannot open file %s\n", (_DWORD)name, v5, v6, v7, v8);
    return (unsigned int)-1;
  }
  v10 = stat_buf.st_size;
  v11 = malloc(stat_buf.st_size);
  v16 = v11;
  if ( !v11 )
  {
    sub_1930AC0((unsigned int)"Cannot malloc %ld bytes.\n", v10, v12, v13, v14, v15);
    goto LABEL_42;
  }
  v21 = fread(v11, 1uLL, v10, v9);
  if ( (int)v21 < stat_buf.st_size )
  {
    sub_1930AC0((unsigned int)"Cannot read from file %s\n", (_DWORD)name, v17, v18, v19, v20);
    free(v16);
LABEL_42:
    v32 = -1;
    fclose(v9);
    return (unsigned int)v32;
  }
  fclose(v9);
  unlink(name);
  sleep(1u);
  if ( a4 )
  {
    memset(v108, 0, sizeof(v108));
    v86 = 1;
  }
  else
  {
    if ( (int)sub_20C1240(a2, v108) < 0 )
    {
      v32 = -1;
      sub_1930AC0((unsigned int)"Cannot read mbr %s\n", (_DWORD)a2, v54, v55, v56, v57);
      free(v16);
      return (unsigned int)v32;
    }
    v86 = sub_20C15E0(v108);
  }
  for ( i = 0; i != 1024; ++i )
  {
    v23 = i;
    close(v23);
  }
  v87 = sub_20D1FE0();
  if ( !v87 || !a3 )
  {
    if ( (unsigned int)sub_436250() )
    {
      v26 = *__errno_location();
      if ( v26 != 22 )
      {
        v85 = "umount shared data partition failed (%d)\n";
        goto LABEL_78;
      }
    }
    a3 = umount("/data");
    if ( a3 )
    {
      v26 = *__errno_location();
      if ( v26 != 22 )
      {
        v85 = "umount data directory failed (%d)\n";
        goto LABEL_78;
      }
      a3 = 0;
    }
  }
  v29 = sub_438410(v16, v21);
  if ( v29 < 0 )
  {
    v26 = *__errno_location();
    v85 = "check_gz_header() failed (%d)\n";
LABEL_78:
    v32 = -1;
    sub_1930AC0((_DWORD)v85, v26, v24, v25, v27, v28);
    free(v16);
    return (unsigned int)v32;
  }
  v99 = 0LL;
  v100 = 0LL;
  v101 = 0LL;
  v30 = inflateInit2_(&stat_loc[1], 4294967281LL, "1.2.11", 112LL);
  v31 = v30;
  if ( v30 )
  {
    v26 = v30;
    v85 = "inflateInit() failed (%d)\n";
    goto LABEL_78;
  }
  stat_loc[3] = v21 - v29;
  v32 = -1;
  *(_QWORD *)&stat_loc[1] = &v16[v29];
  v96 = buf;
  v97 = 512;
  v88 = 0;
  v93 = -1;
  v90 = 1;
  v89 = 1;
  while ( 1 )
  {
    v33 = inflate(&stat_loc[1], 0LL);
    if ( v33 == 1 )
      break;
    if ( v33 )
    {
      sub_1930AC0((unsigned int)"inflate() failed (%d)\n", v33, v34, v35, v36, v37);
      goto LABEL_47;
    }
    if ( !v97 )
    {
      sub_20C0800(buf, 512LL, 0LL);
      v31 += 512;
      if ( v90 )
      {
        if ( (unsigned int)sub_20C13C0(v108, buf) )
        {
          if ( a3 )
          {
            sub_1930AC0(
              (unsigned int)"\nImage with incompatible partition layout cannot \nbe restored to secondary partition.\n",
              a3,
              v61,
              v62,
              v63,
              v64);
            goto LABEL_47;
          }
          qmemcpy(v108, buf, sizeof(v108));
          v32 = open(a2, 66, 511LL);
          if ( v32 < 0 )
          {
            v32 = -1;
            sub_1930AC0((unsigned int)"Cannot open file %s\n", (_DWORD)a2, v81, v82, v83, v84);
            goto LABEL_40;
          }
          sub_2195FD0(s, a2, 0x40uLL);
          v93 = -1;
          v88 = v90;
        }
        else
        {
          if ( !v87 || v86 > 1 && (v89 = 2, (unsigned int)sub_20C1360(v108) != 1) )
            v89 = v90;
          v88 = sub_7A3560(s, 0x40uLL, a2);
          if ( v88 )
          {
            sub_1930AC0((unsigned int)"Error: in function hdconv2,device name invalid\n", 64, v65, v66, v67, v68);
LABEL_47:
            if ( v32 == -1 )
              goto LABEL_40;
            goto LABEL_48;
          }
          if ( (unsigned int)sub_1B2DB90(512LL) )
          {
            fflush(stdout);
            fflush(stderr);
            if ( !fork() )
            {
              argv[0] = "/bin/mke2fs";
              argv[1] = "-b4096";
              argv[2] = "-q";
              argv[3] = s;
              argv[4] = 0LL;
              execve("/bin/mke2fs", argv, &off_336CB20);
              exit(-1);
            }
            wait((__WAIT_STATUS)stat_loc);
          }
          v32 = open(s, 66, 511LL);
          if ( v32 < 0 )
          {
            v32 = -1;
            sub_1930AC0((unsigned int)"Cannot open file %s\n", (unsigned int)s, v69, v70, v71, v72);
            goto LABEL_40;
          }
          v93 = sub_20C14F0(buf);
          sub_20C1560(v108, 1LL);
          if ( (int)sub_20C12B0(a2, v108) < 0 )
          {
            sub_1930AC0((unsigned int)"can't modify mbr\n", (unsigned int)v108, v73, v74, v75, v76);
LABEL_48:
            v58 = v32;
            v32 = -1;
            close(v58);
            goto LABEL_40;
          }
        }
      }
      if ( v31 > v93 && (int)sub_438B90(v32, buf, 512) < 0 )
        goto LABEL_63;
      v96 = buf;
      v97 = 512;
      v90 = 0;
    }
  }
  if ( v98 - v31 > 0 )
  {
    v91 = v98 - v31;
    sub_20C0800(buf, (unsigned int)(v98 - v31), 0LL);
    if ( v31 > v93 && (int)sub_438B90(v32, buf, v91) < 0 )
    {
LABEL_63:
      sub_1930AC0(
        (unsigned int)"Error : Boot image on disk: %s is corrupted, please try to update the firmware again !\n ",
        (unsigned int)s,
        v77,
        v78,
        v79,
        v80);
      goto LABEL_47;
    }
  }
  fsync(v32);
  v38 = v32;
  v39 = 4;
  close(v38);
  v40 = v16 + 10;
  do
  {
    v41 = strchr(v40, 45);
    --v39;
    v40 = v41 + 1;
  }
  while ( v39 );
  v42 = (unsigned __int8 *)(v41 + 1);
  v43 = *__ctype_b_loc();
  while ( (v43[*v42] & 0x800) != 0 )
    ++v42;
  if ( v16 + 10 == v42 )
  {
    v48 = &v104;
  }
  else
  {
    v44 = v16 + 11;
    v46 = &v106;
    v104 = v16[10];
    v47 = v105;
    while ( 1 )
    {
      v48 = v47;
      if ( v42 == v44 )
        break;
      v45 = *v44++;
      *v47++ = v45;
      if ( &v106 == v48 + 1 )
      {
        v48 = &v106;
        break;
      }
    }
  }
  *v48 = 0;
  sub_20C1580(v108, v89, &v104, v44, v45, v46);
  if ( !a3 )
    sub_20C1510(v108, v89);
  if ( !v88 )
    sub_20C1560(v108, 0LL);
  if ( (int)sub_20C12B0(a2, v108) < 0 )
  {
    v32 = -1;
    sub_1930AC0((unsigned int)"can't modify mbr\n", (unsigned int)v108, v49, v50, v51, v52);
  }
  else
  {
    v32 = v98;
    if ( !a3 )
    {
      sync();
      sleep(2u);
      v59 = open(a2, 0);
      v60 = v59;
      if ( v59 >= 0 )
      {
        ioctl(v59, 0x125FuLL);
        close(v60);
        sync();
        sleep(4u);
      }
    }
  }
LABEL_40:
  inflateEnd(&stat_loc[1]);
  free(v16);
  return (unsigned int)v32;
}
```

该函数的主要逻辑为：

- 跳过固件文件的gz header
- 然后用libz库，以512为块进行解压缩
- 对512字节解压缩完毕的内容进行解密 ( 该版本对应的解密函数为 sub_20C0800 )