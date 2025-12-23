```c
// len(key_iv) = 48;32 key + 16 iv
int get_random_aes_256_cbc_key_iv(uint8_t *key_iv)
{
    mbedtls_ctr_drbg_context ctr_drbg;
    mbedtls_entropy_context entropy;
    int ret;
    char *pers = "aes generate key iv";
    int retcode = 0;

    mbedtls_entropy_init(&entropy);
    mbedtls_ctr_drbg_init(&ctr_drbg);

    if ((ret = mbedtls_ctr_drbg_seed(&ctr_drbg, mbedtls_entropy_func, &entropy,
                                     (unsigned char *)pers, strlen(pers))) != 0)
    {
        DLX(0, printf("\tfailed ! mbedtls_ctr_drbg_init returned -0x%04x\n", -ret));
        retcode = -1;
        goto exit;
    }
    if ((ret = mbedtls_ctr_drbg_random(&ctr_drbg, key_iv, 32 + 16)) != 0)
    {
        DLX(0, printf("\tfailed ! mbedtls_ctr_drbg_random returned -0x%04x\n", -ret));
        retcode = -1;
        goto exit;
    }

exit:
    mbedtls_ctr_drbg_free(&ctr_drbg);
    mbedtls_entropy_free(&entropy);

    return retcode;
}

int encrypt_with_rsa_public_key(char *public_key, uint8_t *input, uint32_t input_len,uint8_t *output,uint32_t output_buf_len,uint32_t *out_len)
{
    int ret = 0;
    mbedtls_rsa_context *rsa;
    mbedtls_entropy_context entropy;
    mbedtls_ctr_drbg_context ctr_drbg;
    mbedtls_pk_context ctx_pk;
    const char *pers = "rsa_encrypt";

    mbedtls_ctr_drbg_init(&ctr_drbg);
    mbedtls_entropy_init(&entropy);
    mbedtls_pk_init(&ctx_pk);

    ret = mbedtls_ctr_drbg_seed(&ctr_drbg, mbedtls_entropy_func,
                                &entropy, (const unsigned char *)pers,
                                strlen(pers));
    if (ret != 0)
    {
        DLX(0, printf("\tfailed  ! mbedtls_ctr_drbg_seed returned %d\n", ret));
        goto exit;
    }

    ret = mbedtls_pk_parse_public_key(&ctx_pk, public_key, strlen(public_key) + 1);
    if (ret != 0)
    {
        DLX(0, printf("\t. Can't import public key ! return %d\n", ret));
        goto exit;
    }

    rsa = mbedtls_pk_rsa(ctx_pk);

    if(output_buf_len < (rsa)->MBEDTLS_PRIVATE(len)){
        DLX(0, printf("\t. output_buf_len < rsa->len(%d)\n", (rsa)->MBEDTLS_PRIVATE(len)));
        goto exit;
    }

    /*
     * Calculate the RSA encryption of the hash.
     */
    ret = mbedtls_rsa_pkcs1_encrypt(rsa, mbedtls_ctr_drbg_random,
                                    &ctr_drbg,
                                    input_len, input, output);
    if( ret != 0 )
    {
        DLX(0, printf("\t. mbedtls_rsa_pkcs1_encrypt error ! return %d\n", ret));
        goto exit;
    }

    if(out_len)
        *out_len =  (rsa)->MBEDTLS_PRIVATE(len);

exit:
    mbedtls_ctr_drbg_free(&ctr_drbg);
    mbedtls_entropy_free(&entropy);
    mbedtls_pk_free(&ctx_pk);
    return ret;
}
```

# 库的裁剪

We provide some non-standard configurations focused on specific use cases in the configs/ directory. You can read more about those in configs/README.txt

```
This directory contains example configuration files.

The examples are generally focused on a particular usage case (eg, support for
a restricted number of ciphersuites) and aim at minimizing resource usage for
this target. They can be used as a basis for custom configurations.

These files are complete replacements for the default mbedtls_config.h. To use one of
them, you can pick one of the following methods:

1. Replace the default file include/mbedtls/mbedtls_config.h with the chosen one.

2. Define MBEDTLS_CONFIG_FILE and adjust the include path accordingly.
   For example, using make:

    CFLAGS="-I$PWD/configs -DMBEDTLS_CONFIG_FILE='<foo.h>'" make

   Or, using cmake:

    find . -iname '*cmake*' -not -name CMakeLists.txt -exec rm -rf {} +
    CFLAGS="-I$PWD/configs -DMBEDTLS_CONFIG_FILE='<foo.h>'" cmake .
    make

Note that the second method also works if you want to keep your custom
configuration file outside the Mbed TLS tree.
```



# 资料

error in mbedtls_rsa_rsaes_pkcs1_v15_encrypt #2529

https://github.com/Mbed-TLS/mbedtls/issues/2529

ESP32+Arduino+Mbed TLS实现RSA加密解密

https://zhuanlan.zhihu.com/p/455603665

mbedtls入门和使用

https://blog.csdn.net/weixin_41965270/article/details/88687320

Mbed TLS tutorial

https://mbed-tls.readthedocs.io/en/latest/kb/how-to/mbedtls-tutorial/