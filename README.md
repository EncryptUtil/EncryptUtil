# EncryptUtil

[![JitPack](https://jitpack.io/v/EncryptUtil/EncryptUtil.svg)](https://jitpack.io/#EncryptUtil/EncryptUtil)
[![CI](https://github.com/EncryptUtil/EncryptUtil/workflows/Android%20CI/badge.svg)](https://github.com/EncryptUtil/EncryptUtil/actions)
[![License](https://img.shields.io/badge/license-Apche%202.0-blue.svg)](http://www.apache.org/licenses/LICENSE-2.0)
[![Blog](https://img.shields.io/badge/blog-Jenly-9933CC.svg)](https://jenly1314.github.io/)
[![QQGroup](https://img.shields.io/badge/QQGroup-20867961-blue.svg)](http://shang.qq.com/wpa/qunwpa?idkey=8fcc6a2f88552ea44b1.1.982c94fd124f7bb3ec227e2a400dbbfaad3dc2f5ad)

EncryptUtil 是一个整理了常用加密算法工具类集合。


#### [Standard Algorithm Name Documentation](https://docs.oracle.com/javase/8/docs/technotes/guides/security/StandardNames.html)


## 引入

### Gradle

1. 在Project的 **build.gradle** 里面添加远程仓库  
          
```gradle
allprojects {
    repositories {
        //...
        maven { url 'https://jitpack.io' }
    }
}
```

2. 在Module的 **build.gradle** 里面添加引入依赖项

```gradle
compile 'com.github.EncryptUtil:EncryptUtil:1.0.0'

```

## 示例

#### CipherUtils
```java
    public void testCipher() throws Exception {
        String key16 = "abcdefghij123456";
        String key24 = "abcdefghij12345678901234";
        String data = "abcd1234";

        // AES:29ae13a9fcc71bc649220b7d39d5646a
        System.out.println("AES:" + CipherUtils.aesEncryptToHexString(data.getBytes(),null, key16.getBytes()));
        // AES:abcd1234
        System.out.println("AES:" + new String(CipherUtils.aesDecrypt(CipherUtils.aesEncrypt(data.getBytes(),null, key16.getBytes()),null, key16.getBytes())));

        // DES:7b81376bc511d077
        System.out.println("DES:" + CipherUtils.desEncryptToHexString(data.getBytes(),CipherUtils.DES_ECB_NoPadding, key16.getBytes()));
        // DES:abcd1234
        System.out.println("DES:" + new String(CipherUtils.desDecrypt(CipherUtils.desEncrypt(data.getBytes(),CipherUtils.DES_ECB_NoPadding, key16.getBytes()),CipherUtils.DES_ECB_NoPadding, key16.getBytes())));

        // DESede:33dd13b95f1e4b5d4c78eda39a623b09
        System.out.println("DESede:" + CipherUtils.desEdeEncryptToHexString(data.getBytes(),CipherUtils.DESede_ECB_PKCS5Padding, key24.getBytes()));
        // DESede:abcd1234
        System.out.println("DESede:" + new String(CipherUtils.desEdeDecrypt(CipherUtils.desEdeEncrypt(data.getBytes(),CipherUtils.DESede_ECB_PKCS5Padding, key24.getBytes()),CipherUtils.DESede_ECB_PKCS5Padding, key24.getBytes())));

        // ARCFOUR:3f185b253d062275
        System.out.println("ARCFOUR:" + CipherUtils.arcFourEncryptToHexString(data.getBytes(), key16.getBytes()));
        // ARCFOUR:abcd1234
        System.out.println("ARCFOUR:" + new String(CipherUtils.arcFourDecrypt(CipherUtils.arcFourEncrypt(data.getBytes(), key16.getBytes()), key16.getBytes())));

        KeyPairGenerator keyPairGenerator = KeyPairGenerator.getInstance("RSA");
        keyPairGenerator.initialize(1024);
        KeyPair keyPair = keyPairGenerator.generateKeyPair();
        byte[] publicKey = keyPair.getPublic().getEncoded();
        byte[] privateKey = keyPair.getPrivate().getEncoded();
        System.out.println("publicKey:" + Base64.getEncoder().encodeToString(publicKey));
        System.out.println("privateKey:" + Base64.getEncoder().encodeToString(privateKey));

        byte[] rsaEncrypt = CipherUtils.rsaEncrypt(data.getBytes(),publicKey);
        System.out.println("RSA-Encrypt:" + Base64.getEncoder().encodeToString(rsaEncrypt));
        System.out.println("RSA-Decrypt:" + new String(CipherUtils.rsaDecrypt(rsaEncrypt, privateKey)));

        // Blowfish:d73c2a4007f899ac3cc64298fb85cd51
        String blowfishEncrypt = CipherUtils.encryptToHexString(data.getBytes(),null, CipherUtils.Blowfish, key16.getBytes(),null);
        System.out.println("Blowfish:" + blowfishEncrypt);
        // Blowfish:abcd1234
        System.out.println("Blowfish:" + CipherUtils.decryptHexStringToString(blowfishEncrypt,null, CipherUtils.Blowfish, key16.getBytes(),null));

        // RC2:69ba68358111bd7bc34c561d5a301096
        String rc2Encrypt = CipherUtils.encryptToHexString(data.getBytes(),null, CipherUtils.RC2, key16.getBytes(),null);
        System.out.println("RC2:" + rc2Encrypt);
        // RC2:abcd1234
        System.out.println("RC2:" + CipherUtils.decryptHexStringToString(rc2Encrypt,null, CipherUtils.RC2, key16.getBytes(),null));

        // RC4:3f185b253d062275
        String rc4Encrypt = CipherUtils.encryptToHexString(data.getBytes(),null, CipherUtils.RC4, key16.getBytes(),null);
        System.out.println("RC4:" + rc4Encrypt);
        // RC4:abcd1234
        System.out.println("RC4:" + CipherUtils.decryptHexStringToString(rc4Encrypt,null, CipherUtils.RC4, key16.getBytes(),null));

    }


```

#### MacUtils
```java
    public void testMac(){
        String key = "abcdefghij123456";
        String data = "abcd1234";
        // HmacMD5:79316c0e2fc48480499213878d4bb6a4
        System.out.println("HmacMD5:" + MacUtils.hMacMd5(data,key.getBytes()));
        // HmacSHA1:0bfbe855871b46f773afde5d11243285a32035e3
        System.out.println("HmacSHA1:" + MacUtils.hMacSha1(data,key.getBytes()));
        // HmacSHA224:f9fdef786b93cba89ded93a00a82170f0b3406a937308f30b7cc5b16
        System.out.println("HmacSHA224:" + MacUtils.hMacSha224(data,key.getBytes()));
        // HmacSHA256:d788da48fd740ee3c6303698219089ea311172b86c762868f6f480de1269c82d
        System.out.println("HmacSHA256:" + MacUtils.hMacSha256(data,key.getBytes()));
        // HmacSHA384:e4d7d8dcb050143815fd17f3e73cd8b17aade73bb372908e051f6465c6a13917a036fdd1f297442eb3ef7c98af1e70e9
        System.out.println("HmacSHA384:" + MacUtils.hMacSha384(data,key.getBytes()));
        // HmacSHA512:c807de68ccc56c18403f89cc811f42588c1bd20a0110f4dc6216bb7d59ffba54fb4d7c432ef1f13284972c6ba2d532ae1d52459063dbd85aab97d5b5c4bf5e78
        System.out.println("HmacSHA512:" + MacUtils.hMacSha512(data,key.getBytes()));

    }


```

#### MessageDigestUtils
```java
    public void testMessageDigest(){
        String data = "abcd1234";
        // MD2:6d783f8193a895c3e9c24e45c83aa4e7
        System.out.println("MD2:" + MessageDigestUtils.md2(data));
        // MD5:e19d5cd5af0378da05f63f891c7467af
        System.out.println("MD5:" + MessageDigestUtils.md5(data));
        // SHA1:7ce0359f12857f2a90c7de465f40a95f01cb5da9
        System.out.println("SHA1:" + MessageDigestUtils.sha1(data));
        // SHA224:375e94d73b1a7391aa8030cdf5c769deea96a6c97863bdac49f14a78
        System.out.println("SHA224:" + MessageDigestUtils.sha224(data));
        // SHA256:e9cee71ab932fde863338d08be4de9dfe39ea049bdafb342ce659ec5450b69ae
        System.out.println("SHA256:" + MessageDigestUtils.sha256(data));
        // SHA384:ccd30e4ffacb44db598f1130cacff9d5a79ea234ca6242a9eaecacb629e5e637236a6ee452c819b54a13c7e706fb5a7b
        System.out.println("SHA384:" + MessageDigestUtils.sha384(data));
        // SHA512:925f43c3cfb956bbe3c6aa8023ba7ad5cfa21d104186fffc69e768e55940d9653b1cd36fba614fba2e1844f4436da20f83750c6ec1db356da154691bdd71a9b1
        System.out.println("SHA512:" + MessageDigestUtils.sha512(data));
        // SHA512/224:f9ecb22a5aab8d4ccfdbe371699362eec0d66de2e6aba7d191fbb1d9
        System.out.println("SHA512/224:" + MessageDigestUtils.sha512_224(data));
        // SHA512/256:e44e0cccd862ac14be6dd245a266a08ad76dd0091d74f41ae25f604f35c16e89
        System.out.println("SHA512/256:" + MessageDigestUtils.sha512_256(data));
    }

```

#### SignatureUtils
```java
    public void testSignature() throws Exception{
        String data = "abcd1234";
        KeyPairGenerator keyPairGenerator = KeyPairGenerator.getInstance("RSA");
        keyPairGenerator.initialize(1024);
        KeyPair keyPair = keyPairGenerator.generateKeyPair();
        PublicKey publicKey = keyPair.getPublic();
        PrivateKey privateKey = keyPair.getPrivate();

        byte[] sign = SignatureUtils.sign(data.getBytes(),SignatureUtils.MD5withRSA,privateKey);
        System.out.println("sign:" + Base64.getEncoder().encodeToString(sign));
        System.out.println("verify:" + SignatureUtils.verify(data.getBytes(),sign,SignatureUtils.MD5withRSA,publicKey));
    }

```


