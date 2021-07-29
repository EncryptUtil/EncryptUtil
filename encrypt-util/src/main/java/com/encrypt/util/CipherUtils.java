package com.encrypt.util;

import javax.crypto.*;
import javax.crypto.spec.DESKeySpec;
import javax.crypto.spec.DESedeKeySpec;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import java.security.*;
import java.security.spec.AlgorithmParameterSpec;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;

/**
 * {@link Cipher}
 * @see <a href="https://docs.oracle.com/javase/8/docs/technotes/guides/security/StandardNames.html#Cipher">Standard Algorithm Name Documentation</a>
 * @author <a href="mailto:jenly1314@gmail.com">Jenly</a>
 */
public final class CipherUtils {

    //-------------------- algorithm --------------------//
    public static final String AES = "AES";

    public static final String AESWrap = "AESWrap";
    public static final String ARCFOUR = "ARCFOUR";
    public static final String Blowfish = "Blowfish";

    public static final String DES = "DES";

    public static final String DESede = "DESede";

    public static final String DESedeWrap = "DESedeWrap";
//    public static final String ECIES = "ECIES";//暂不支持

    public static final String RC2 = "RC2";
    public static final String RC4 = "RC4";
//    public static final String RC5 = "RC5";//暂不支持
    public static final String RSA = "RSA";
    //-------------------- algorithm end --------------------//


    //-------------------- transformation --------------------//
    /*
      The algorithms are specified as transformations. Implementations must support the key sizes in parentheses.
     */
    // 参数格式：算法/模式/填充模式
    public static final String AES_CBC_NoPadding = "AES/CBC/NoPadding";// (128)
    public static final String AES_CBC_PKCS5Padding = "AES/CBC/PKCS5Padding";// (128)
    public static final String AES_ECB_NoPadding = "AES/ECB/NoPadding";// (128)
    public static final String AES_ECB_PKCS5Padding = "AES/ECB/PKCS5Padding";// (128)

    public static final String DES_CBC_NoPadding = "DES/CBC/NoPadding";// (56)
    public static final String DES_CBC_PKCS5Padding = "DES/CBC/PKCS5Padding";// (56)
    public static final String DES_ECB_NoPadding = "DES/ECB/NoPadding";// (56)
    public static final String DES_ECB_PKCS5Padding = "DES/ECB/PKCS5Padding";// (56)

    public static final String DESede_CBC_NoPadding = "DESede/CBC/NoPadding";// (168)
    public static final String DESede_CBC_PKCS5Padding = "DESede/CBC/PKCS5Padding";// (168)
    public static final String DESede_ECB_NoPadding = "DESede/ECB/NoPadding";// (168)
    public static final String DESede_ECB_PKCS5Padding = "DESede/ECB/PKCS5Padding";// (168)

    public static final String RSA_ECB_PKCS1Padding = "RSA/ECB/PKCS1Padding";// (1024, 2048)
    public static final String RSA_ECB_OAEPWithSHA_1AndMGF1Padding = "RSA/ECB/OAEPWithSHA-1AndMGF1Padding";// (1024, 2048)
    public static final String RSA_ECB_OAEPWithSHA_256AndMGF1Padding = "RSA/ECB/OAEPWithSHA-256AndMGF1Padding";// (1024, 2048)
    //-------------------- transformation end --------------------//

    private CipherUtils(){

    }

    //-------------------- AES begin --------------------//

    /**
     * AES加密
     * @param data 需要加解密的数据
     * @param transformation transformation的格式：算法/模式/填充模式
     * @param key 秘钥
     * @return
     */
    public static byte[] aesEncrypt(byte[] data, String transformation, byte[] key){
        return aesEncrypt(data, transformation, key, null);
    }

    /**
     * AES加密
     * @param data 需要加解密的数据
     * @param transformation transformation的格式：算法/模式/填充模式
     * @param key 秘钥
     * @param ivParameter 向量：当transformation中的模式为 “CBC” 时需传向量，当模式为“ECB”时，没有向量，传空即可
     * @return
     */
    public static byte[] aesEncrypt(byte[] data, String transformation, byte[] key, byte[] ivParameter){
        return encrypt(data, transformation, AES, key, ivParameter);
    }

    /**
     * AES加密
     * @param data 需要加解密的数据
     * @param transformation transformation的格式：算法/模式/填充模式
     * @param key 秘钥
     * @return
     */
    public static String aesEncryptToHexString(byte[] data, String transformation, byte[] key){
        return aesEncryptToHexString(data, transformation, key, null);
    }

    /**
     * AES加密
     * @param data 需要加解密的数据
     * @param transformation transformation的格式：算法/模式/填充模式
     * @param key 秘钥
     * @param ivParameter 向量：当transformation中的模式为 “CBC” 时需传向量，当模式为“ECB”时，没有向量，传空即可
     * @return
     */
    public static String aesEncryptToHexString(byte[] data, String transformation, byte[] key, byte[] ivParameter){
        return encryptToHexString(data, transformation, AES, key, ivParameter);
    }

    /**
     * AES解密
     * @param data 需要加解密的数据
     * @param transformation transformation的格式：算法/模式/填充模式
     * @param key 秘钥
     * @return
     */
    public static byte[] aesDecrypt(byte[] data, String transformation, byte[] key){
        return aesDecrypt(data, transformation, key, null);
    }

    /**
     * AES解密
     * @param data 需要加解密的数据
     * @param transformation transformation的格式：算法/模式/填充模式
     * @param key 秘钥
     * @param ivParameter 向量：当transformation中的模式为 “CBC” 时需传向量，当模式为“ECB”时，没有向量，传空即可
     * @return
     */
    public static byte[] aesDecrypt(byte[] data, String transformation, byte[] key, byte[] ivParameter){
        return decrypt(data, transformation, AES, key, ivParameter);
    }

    /**
     * AES解密
     * @param data 需要加解密的数据
     * @param transformation transformation的格式：算法/模式/填充模式
     * @param key 秘钥
     * @return
     */
    public static String aesDecryptToString(byte[] data, String transformation, byte[] key){
        return aesDecryptToString(data, transformation, key, null);
    }

    /**
     * AES解密
     * @param data 需要加解密的数据
     * @param transformation transformation的格式：算法/模式/填充模式
     * @param key 秘钥
     * @param ivParameter 向量：当transformation中的模式为 “CBC” 时需传向量，当模式为“ECB”时，没有向量，传空即可
     * @return
     */
    public static String aesDecryptToString(byte[] data, String transformation, byte[] key, byte[] ivParameter){
        return decryptToString(data, transformation, AES, key, ivParameter);
    }

    /**
     * AES解密
     * @param hexString 十六进制的字符串
     * @param transformation transformation的格式：算法/模式/填充模式
     * @param key 秘钥
     * @return
     */
    public static String aesDecryptHexStringToString(String hexString, String transformation, byte[] key){
        return aesDecryptHexStringToString(hexString, transformation, key, null);
    }

    /**
     * AES解密
     * @param hexString 十六进制的字符串
     * @param transformation transformation的格式：算法/模式/填充模式
     * @param key 秘钥
     * @param ivParameter 向量：当transformation中的模式为 “CBC” 时需传向量，当模式为“ECB”时，没有向量，传空即可
     * @return
     */
    public static String aesDecryptHexStringToString(String hexString, String transformation, byte[] key, byte[] ivParameter){
        return decryptHexStringToString(hexString, transformation, AES, key, ivParameter);
    }

    //-------------------- AES end --------------------//

    //-------------------- DES begin --------------------//

    /**
     * DES加密
     * @param data 需要加解密的数据
     * @param transformation transformation的格式：算法/模式/填充模式
     * @param key 秘钥
     * @return
     */
    public static byte[] desEncrypt(byte[] data, String transformation, byte[] key){
        return desEncrypt(data, transformation, key, null);
    }

    /**
     * DES加密
     * @param data 需要加解密的数据
     * @param transformation transformation的格式：算法/模式/填充模式
     * @param key 秘钥
     * @param ivParameter 向量：当transformation中的模式为 “CBC” 时需传向量，当模式为“ECB”时，没有向量，传空即可
     * @return
     */
    public static byte[] desEncrypt(byte[] data, String transformation, byte[] key, byte[] ivParameter){
        return encrypt(data, transformation, DES, key, ivParameter);
    }

    /**
     * DES加密
     * @param data 需要加解密的数据
     * @param transformation transformation的格式：算法/模式/填充模式
     * @param key 秘钥
     * @return
     */
    public static String desEncryptToHexString(byte[] data, String transformation, byte[] key){
        return desEncryptToHexString(data, transformation, key, null);
    }

    /**
     * DES加密
     * @param data 需要加解密的数据
     * @param transformation transformation的格式：算法/模式/填充模式
     * @param key 秘钥
     * @param ivParameter 向量：当transformation中的模式为 “CBC” 时需传向量，当模式为“ECB”时，没有向量，传空即可
     * @return
     */
    public static String desEncryptToHexString(byte[] data, String transformation, byte[] key, byte[] ivParameter){
        return encryptToHexString(data, transformation, DES, key, ivParameter);
    }

    /**
     * DES解密
     * @param data 需要加解密的数据
     * @param transformation transformation的格式：算法/模式/填充模式
     * @param key 秘钥
     * @return
     */
    public static byte[] desDecrypt(byte[] data, String transformation, byte[] key){
        return desDecrypt(data, transformation, key, null);
    }

    /**
     * DES解密
     * @param data 需要加解密的数据
     * @param transformation transformation的格式：算法/模式/填充模式
     * @param key 秘钥
     * @param ivParameter 向量：当transformation中的模式为 “CBC” 时需传向量，当模式为“ECB”时，没有向量，传空即可
     * @return
     */
    public static byte[] desDecrypt(byte[] data, String transformation, byte[] key, byte[] ivParameter){
        return decrypt(data, transformation, DES, key, ivParameter);
    }

    /**
     * DES解密
     * @param data 需要加解密的数据
     * @param transformation transformation的格式：算法/模式/填充模式
     * @param key 秘钥
     * @return
     */
    public static String desDecryptToString(byte[] data, String transformation, byte[] key){
        return desDecryptToString(data, transformation, key, null);
    }

    /**
     * DES解密
     * @param data 需要加解密的数据
     * @param transformation transformation的格式：算法/模式/填充模式
     * @param key 秘钥
     * @param ivParameter 向量：当transformation中的模式为 “CBC” 时需传向量，当模式为“ECB”时，没有向量，传空即可
     * @return
     */
    public static String desDecryptToString(byte[] data, String transformation, byte[] key, byte[] ivParameter){
        return decryptToString(data, transformation, DES, key, ivParameter);
    }

    /**
     * DES解密
     * @param hexString 十六进制的字符串
     * @param transformation transformation的格式：算法/模式/填充模式
     * @param key 秘钥
     * @return
     */
    public static String desDecryptHexStringToString(String hexString, String transformation, byte[] key){
        return desDecryptHexStringToString(hexString, transformation, key, null);
    }

    /**
     * DES解密
     * @param hexString 十六进制的字符串
     * @param transformation transformation的格式：算法/模式/填充模式
     * @param key 秘钥
     * @param ivParameter 向量：当transformation中的模式为 “CBC” 时需传向量，当模式为“ECB”时，没有向量，传空即可
     * @return
     */
    public static String desDecryptHexStringToString(String hexString, String transformation, byte[] key, byte[] ivParameter){
        return decryptHexStringToString(hexString, transformation, DES, key, ivParameter);
    }

    //-------------------- DES end --------------------//


    //-------------------- DESede begin --------------------//

    /**
     * DESede加密
     * @param data 需要加解密的数据
     * @param transformation transformation的格式：算法/模式/填充模式
     * @param key 秘钥
     * @return
     */
    public static byte[] desEdeEncrypt(byte[] data, String transformation, byte[] key){
        return desEdeEncrypt(data, transformation, key, null);
    }

    /**
     * DESede加密
     * @param data 需要加解密的数据
     * @param transformation transformation的格式：算法/模式/填充模式
     * @param key 秘钥
     * @param ivParameter 向量：当transformation中的模式为 “CBC” 时需传向量，当模式为“ECB”时，没有向量，传空即可
     * @return
     */
    public static byte[] desEdeEncrypt(byte[] data, String transformation, byte[] key, byte[] ivParameter){
        return encrypt(data, transformation, DESede, key, ivParameter);
    }

    /**
     * DESede加密
     * @param data 需要加解密的数据
     * @param transformation transformation的格式：算法/模式/填充模式
     * @param key 秘钥
     * @return
     */
    public static String desEdeEncryptToHexString(byte[] data, String transformation, byte[] key){
        return desEdeEncryptToHexString(data, transformation, key, null);
    }

    /**
     * DESede加密
     * @param data 需要加解密的数据
     * @param transformation transformation的格式：算法/模式/填充模式
     * @param key 秘钥
     * @param ivParameter 向量：当transformation中的模式为 “CBC” 时需传向量，当模式为“ECB”时，没有向量，传空即可
     * @return
     */
    public static String desEdeEncryptToHexString(byte[] data, String transformation, byte[] key, byte[] ivParameter){
        return encryptToHexString(data, transformation, DESede, key, ivParameter);
    }

    /**
     * DESede解密
     * @param data 需要加解密的数据
     * @param transformation transformation的格式：算法/模式/填充模式
     * @param key 秘钥
     * @return
     */
    public static byte[] desEdeDecrypt(byte[] data, String transformation, byte[] key){
        return desEdeDecrypt(data, transformation, key, null);
    }

    /**
     * DESede解密
     * @param data 需要加解密的数据
     * @param transformation transformation的格式：算法/模式/填充模式
     * @param key 秘钥
     * @param ivParameter 向量：当transformation中的模式为 “CBC” 时需传向量，当模式为“ECB”时，没有向量，传空即可
     * @return
     */
    public static byte[] desEdeDecrypt(byte[] data, String transformation, byte[] key, byte[] ivParameter){
        return decrypt(data, transformation, DESede, key, ivParameter);
    }

    /**
     * DESede解密
     * @param data 需要加解密的数据
     * @param transformation transformation的格式：算法/模式/填充模式
     * @param key 秘钥
     * @return
     */
    public static String desEdeDecryptToString(byte[] data, String transformation, byte[] key){
        return desEdeDecryptToString(data, transformation, key, null);
    }

    /**
     * DESede解密
     * @param data 需要加解密的数据
     * @param transformation transformation的格式：算法/模式/填充模式
     * @param key 秘钥
     * @param ivParameter 向量：当transformation中的模式为 “CBC” 时需传向量，当模式为“ECB”时，没有向量，传空即可
     * @return
     */
    public static String desEdeDecryptToString(byte[] data, String transformation, byte[] key, byte[] ivParameter){
        return decryptToString(data, transformation, DESede, key, ivParameter);
    }

    /**
     * DESede解密
     * @param hexString 十六进制的字符串
     * @param transformation transformation的格式：算法/模式/填充模式
     * @param key 秘钥
     * @return
     */
    public static String desEdeDecryptHexStringToString(String hexString, String transformation, byte[] key){
        return desEdeDecryptHexStringToString(hexString, transformation, key, null);
    }

    /**
     * DESede解密
     * @param hexString 十六进制的字符串
     * @param transformation transformation的格式：算法/模式/填充模式
     * @param key 秘钥
     * @param ivParameter 向量：当transformation中的模式为 “CBC” 时需传向量，当模式为“ECB”时，没有向量，传空即可
     * @return
     */
    public static String desEdeDecryptHexStringToString(String hexString, String transformation, byte[] key, byte[] ivParameter){
        return decryptHexStringToString(hexString, transformation, DESede, key, ivParameter);
    }

    //-------------------- DESede end --------------------//

    //-------------------- ARCFOUR begin --------------------//

    /**
     * ARCFOUR（RC4）加密
     * @param data 需要加解密的数据
     * @param key 秘钥
     * @return
     */
    public static byte[] arcFourEncrypt(byte[] data, byte[] key){
        return arcFourEncrypt(data, key, null);
    }

    /**
     * ARCFOUR（RC4）加密
     * @param data 需要加解密的数据
     * @param key 秘钥
     * @param ivParameter 向量：当transformation中的模式为 “CBC” 时需传向量，当模式为“ECB”时，没有向量，传空即可
     * @return
     */
    public static byte[] arcFourEncrypt(byte[] data, byte[] key, byte[] ivParameter){
        return encrypt(data,null, ARCFOUR, key, ivParameter);
    }

    /**
     * ARCFOUR（RC4）加密
     * @param data 需要加解密的数据
     * @param key 秘钥
     * @return
     */
    public static String arcFourEncryptToHexString(byte[] data, byte[] key){
        return arcFourEncryptToHexString(data, key, null);
    }

    /**
     * ARCFOUR（RC4）加密
     * @param data 需要加解密的数据
     * @param key 秘钥
     * @param ivParameter 向量：当transformation中的模式为 “CBC” 时需传向量，当模式为“ECB”时，没有向量，传空即可
     * @return
     */
    public static String arcFourEncryptToHexString(byte[] data, byte[] key, byte[] ivParameter){
        return encryptToHexString(data,null, ARCFOUR, key, ivParameter);
    }

    /**
     * ARCFOUR（RC4）解密
     * @param data 需要加解密的数据
     * @param key 秘钥
     * @return
     */
    public static byte[] arcFourDecrypt(byte[] data, byte[] key){
        return arcFourDecrypt(data, key, null);
    }

    /**
     * ARCFOUR（RC4）解密
     * @param data 需要加解密的数据
     * @param key 秘钥
     * @param ivParameter 向量：当transformation中的模式为 “CBC” 时需传向量，当模式为“ECB”时，没有向量，传空即可
     * @return
     */
    public static byte[] arcFourDecrypt(byte[] data, byte[] key, byte[] ivParameter){
        return decrypt(data,null, ARCFOUR, key, ivParameter);
    }

    /**
     * ARCFOUR（RC4）解密
     * @param data 需要加解密的数据
     * @param key 秘钥
     * @return
     */
    public static String arcFourDecryptToString(byte[] data, byte[] key){
        return arcFourDecryptToString(data, key, null);
    }

    /**
     * ARCFOUR（RC4）解密
     * @param data 需要加解密的数据
     * @param key 秘钥
     * @param ivParameter 向量：当transformation中的模式为 “CBC” 时需传向量，当模式为“ECB”时，没有向量，传空即可
     * @return
     */
    public static String arcFourDecryptToString(byte[] data, byte[] key, byte[] ivParameter){
        return decryptToString(data,null, ARCFOUR, key, ivParameter);
    }

    /**
     * ARCFOUR（RC4）解密
     * @param hexString 十六进制的字符串
     * @param key 秘钥
     * @return
     */
    public static String arcFourDecryptHexStringToString(String hexString, byte[] key){
        return arcFourDecryptHexStringToString(hexString, key, null);
    }

    /**
     * ARCFOUR（RC4）解密
     * @param hexString 十六进制的字符串
     * @param key 秘钥
     * @param ivParameter 向量：当transformation中的模式为 “CBC” 时需传向量，当模式为“ECB”时，没有向量，传空即可
     * @return
     */
    public static String arcFourDecryptHexStringToString(String hexString, byte[] key, byte[] ivParameter){
        return decryptHexStringToString(hexString,null, ARCFOUR, key, ivParameter);
    }

    //-------------------- ARCFOUR end --------------------//

    //-------------------- RSA begin --------------------//

    /**
     * RSA加密
     * @param data 需要加解密的数据
     * @param publicKey 公钥
     * @return
     */
    public static byte[] rsaEncrypt(byte[] data, byte[] publicKey){
        return rsaEncrypt(data, publicKey, null);
    }

    /**
     * RSA加密
     * @param data 需要加解密的数据
     * @param publicKey 公钥
     * @param ivParameter 向量：当transformation中的模式为 “CBC” 时需传向量，当模式为“ECB”时，没有向量，传空即可
     * @return
     */
    public static byte[] rsaEncrypt(byte[] data, byte[] publicKey, byte[] ivParameter){
        return encrypt(data,null, RSA, publicKey, ivParameter);
    }

    /**
     * RSA加密
     * @param data 需要加解密的数据
     * @param publicKey 公钥
     * @return
     */
    public static String rsaEncryptToHexString(byte[] data, byte[] publicKey){
        return rsaEncryptToHexString(data, publicKey, null);
    }

    /**
     * RSA加密
     * @param data 需要加解密的数据
     * @param publicKey 公钥
     * @param ivParameter 向量：当transformation中的模式为 “CBC” 时需传向量，当模式为“ECB”时，没有向量，传空即可
     * @return
     */
    public static String rsaEncryptToHexString(byte[] data, byte[] publicKey, byte[] ivParameter){
        return encryptToHexString(data,null, RSA, publicKey, ivParameter);
    }

    /**
     * RSA解密
     * @param data 需要加解密的数据
     * @param privateKey 私钥
     * @return
     */
    public static byte[] rsaDecrypt(byte[] data, byte[] privateKey){
        return rsaDecrypt(data, privateKey, null);
    }

    /**
     * RSA解密
     * @param data 需要加解密的数据
     * @param privateKey 私钥
     * @param ivParameter 向量：当transformation中的模式为 “CBC” 时需传向量，当模式为“ECB”时，没有向量，传空即可
     * @return
     */
    public static byte[] rsaDecrypt(byte[] data, byte[] privateKey, byte[] ivParameter){
        return decrypt(data,null, RSA, privateKey, ivParameter);
    }

    /**
     * RSA解密
     * @param data 需要加解密的数据
     * @param privateKey 私钥
     * @return
     */
    public static String rsaDecryptToString(byte[] data, byte[] privateKey){
        return rsaDecryptToString(data, privateKey, null);
    }

    /**
     * RSA解密
     * @param data 需要加解密的数据
     * @param privateKey 私钥
     * @param ivParameter 向量：当transformation中的模式为 “CBC” 时需传向量，当模式为“ECB”时，没有向量，传空即可
     * @return
     */
    public static String rsaDecryptToString(byte[] data, byte[] privateKey, byte[] ivParameter){
        return decryptToString(data,null, RSA, privateKey, ivParameter);
    }

    /**
     * RSA解密
     * @param hexString 十六进制的字符串
     * @param privateKey 私钥
     * @return
     */
    public static String rsaDecryptHexStringToString(String hexString, byte[] privateKey){
        return rsaDecryptHexStringToString(hexString, privateKey, null);
    }

    /**
     * RSA解密
     * @param hexString 十六进制的字符串
     * @param privateKey 私钥
     * @param ivParameter 向量：当transformation中的模式为 “CBC” 时需传向量，当模式为“ECB”时，没有向量，传空即可
     * @return
     */
    public static String rsaDecryptHexStringToString(String hexString, byte[] privateKey, byte[] ivParameter){
        return decryptHexStringToString(hexString,null, RSA, privateKey, ivParameter);
    }

    //-------------------- RSA end --------------------//


    //-------------------- Encrypt begin --------------------//
    /**
     * 加密
     * @param data 需要加解密的数据
     * @param algorithm 算法
     * @param key 秘钥
     * @param ivParameter 向量：当transformation中的模式为 “CBC” 时需传向量，当模式为“ECB”时，没有向量，传空即可
     * @return
     */
    public static String encryptToHexString(byte[] data, String transformation, String algorithm, byte[] key, byte[] ivParameter){
        byte[] result = encrypt(data, transformation, algorithm, key, ivParameter);
        return HexUtils.byteArrayToHexString(result);
    }

    /**
     * 加密
     * @param data 需要加解密的数据
     * @param transformation transformation的格式：算法/模式/填充模式
     * @param algorithm 算法
     * @param key 秘钥
     * @param ivParameter 向量：当transformation中的模式为 “CBC” 时需传向量，当模式为“ECB”时，没有向量，传空即可
     * @return
     */
    public static byte[] encrypt(byte[] data, String transformation, String algorithm, byte[] key, byte[] ivParameter){
        return cipher(data, transformation, algorithm, key, ivParameter, Cipher.ENCRYPT_MODE);
    }

    //-------------------- Encrypt end --------------------//

    //-------------------- Decrypt begin --------------------//
    /**
     * 解密
     * @param hexString 十六进制的字符串
     * @param transformation transformation的格式：算法/模式/填充模式
     * @param algorithm 算法
     * @param key 秘钥
     * @param ivParameter 向量：当transformation中的模式为 “CBC” 时需传向量，当模式为“ECB”时，没有向量，传空即可
     * @return
     */
    public static String decryptHexStringToString(String hexString, String transformation, String algorithm, byte[] key, byte[] ivParameter){
        byte[] result = decryptHexString(hexString, transformation, algorithm, key, ivParameter);
        return result != null ? new String(result) : null;
    }

    /**
     * 解密
     * @param hexString 十六进制的字符串
     * @param transformation transformation的格式：算法/模式/填充模式
     * @param algorithm 算法
     * @param key 秘钥
     * @param ivParameter 向量：当transformation中的模式为 “CBC” 时需传向量，当模式为“ECB”时，没有向量，传空即可
     * @return
     */
    public static byte[] decryptHexString(String hexString, String transformation, String algorithm, byte[] key, byte[] ivParameter){
        byte[] data = HexUtils.hexToByteArray(hexString);
        return decrypt(data, transformation, algorithm, key, ivParameter);
    }

    /**
     * 解密
     * @param data 需要加解密的数据
     * @param transformation transformation的格式：算法/模式/填充模式
     * @param algorithm 算法
     * @param key 秘钥
     * @param ivParameter 向量：当transformation中的模式为 “CBC” 时需传向量，当模式为“ECB”时，没有向量，传空即可
     * @return
     */
    public static String decryptToString(byte[] data, String transformation, String algorithm, byte[] key, byte[] ivParameter){
        byte[] result = decrypt(data, transformation, algorithm, key, ivParameter);
        return result != null ? new String(result) : null;
    }


    /**
     * 解密
     * @param data 需要加解密的数据
     * @param transformation transformation的格式：算法/模式/填充模式
     * @param algorithm 算法
     * @param key 秘钥
     * @param ivParameter 向量：当transformation中的模式为 “CBC” 时需传向量，当模式为“ECB”时，没有向量，传空即可
     * @return
     */
    public static byte[] decrypt(byte[] data, String transformation, String algorithm, byte[] key, byte[] ivParameter){
        return cipher(data, transformation, algorithm, key, ivParameter, Cipher.DECRYPT_MODE);
    }

    //-------------------- Decrypt end --------------------//


    //-------------------- Wrap begin --------------------//

    /**
     * Wrap
     * @param data 需要加解密的数据
     * @param transformation transformation的格式：算法/模式/填充模式
     * @param algorithm 算法
     * @param key 秘钥
     * @param ivParameter 向量：当transformation中的模式为 “CBC” 时需传向量，当模式为“ECB”时，没有向量，传空即可
     * @return
     */
    public static String wrapToHexString(byte[] data, String transformation, String algorithm, byte[] key, byte[] ivParameter){
        byte[] result = wrap(data, transformation, algorithm, key, ivParameter);
        return HexUtils.byteArrayToHexString(result);
    }
    /**
     * Wrap
     * @param data 需要加解密的数据
     * @param transformation transformation的格式：算法/模式/填充模式
     * @param algorithm 算法
     * @param key 秘钥
     * @param ivParameter 向量：当transformation中的模式为 “CBC” 时需传向量，当模式为“ECB”时，没有向量，传空即可
     * @return
     */
    public static byte[] wrap(byte[] data, String transformation, String algorithm, byte[] key, byte[] ivParameter){
        return cipher(data, transformation, algorithm, key, ivParameter, Cipher.WRAP_MODE);
    }

    //-------------------- Wrap end --------------------//


    //-------------------- Unwrap begin --------------------//
    /**
     * Unwrap
     * @param hexString 十六进制的字符串
     * @param transformation transformation的格式：算法/模式/填充模式
     * @param algorithm 算法
     * @param key 秘钥
     * @param ivParameter 向量：当transformation中的模式为 “CBC” 时需传向量，当模式为“ECB”时，没有向量，传空即可
     * @return
     */
    public static String unwrapHexStringToString(String hexString, String transformation, String algorithm, byte[] key, byte[] ivParameter){
        byte[] result = unwrapHexString(hexString, transformation, algorithm, key, ivParameter);
        return result != null ? new String(result) : null;
    }

    /**
     * Unwrap
     * @param hexString 十六进制的字符串
     * @param transformation transformation的格式：算法/模式/填充模式
     * @param algorithm 算法
     * @param key 秘钥
     * @param ivParameter 向量：当transformation中的模式为 “CBC” 时需传向量，当模式为“ECB”时，没有向量，传空即可
     * @return
     */
    public static byte[] unwrapHexString(String hexString, String transformation, String algorithm, byte[] key, byte[] ivParameter){
        byte[] data = HexUtils.hexToByteArray(hexString);
        return unwrap(data, transformation, algorithm, key, ivParameter);
    }

    /**
     * Unwrap
     * @param data 需要加解密的数据
     * @param transformation transformation的格式：算法/模式/填充模式
     * @param algorithm 算法
     * @param key 秘钥
     * @param ivParameter 向量：当transformation中的模式为 “CBC” 时需传向量，当模式为“ECB”时，没有向量，传空即可
     * @return
     */
    public static String unwrapToString(byte[] data, String transformation, String algorithm, byte[] key, byte[] ivParameter){
        byte[] result = unwrap(data, transformation, algorithm, key, ivParameter);
        return result != null ? new String(result) : null;
    }

    /**
     * Unwrap
     * @param data 需要加解密的数据
     * @param transformation transformation的格式：算法/模式/填充模式
     * @param algorithm 算法
     * @param key 秘钥
     * @param ivParameter 向量：当transformation中的模式为 “CBC” 时需传向量，当模式为“ECB”时，没有向量，传空即可
     * @return
     */
    public static byte[] unwrap(byte[] data, String transformation, String algorithm, byte[] key, byte[] ivParameter){
        return cipher(data, transformation, algorithm, key, ivParameter, Cipher.UNWRAP_MODE);
    }

    //-------------------- Unwrap end --------------------//


    /**
     * 通用的加解密
     * @param data 需要加解密的数据
     * @param transformation transformation的格式：算法/模式/填充模式
     * @param algorithm 算法
     * @param key 秘钥
     * @param ivParameter 向量：当transformation中的模式为 “CBC” 时需传向量，当模式为“ECB”时，没有向量，传空即可
     * @param mode {@link Cipher#ENCRYPT_MODE} or {@link Cipher#DECRYPT_MODE} or {@link Cipher#WRAP_MODE} or {@link Cipher#UNWRAP_MODE}
     * @return
     */
    public static byte[] cipher(byte[] data, String transformation, String algorithm, byte[] key,byte[] ivParameter, int mode){
        IvParameterSpec ivParameterSpec = null;
        if(ivParameter != null){
            ivParameterSpec = new IvParameterSpec(ivParameter);
        }
        return cipher(data, transformation, algorithm, obtainKey(key, algorithm, mode), ivParameterSpec, mode);
    }

    /**
     * 通用的加解密
     * @param data 需要加解密的数据
     * @param transformation transformation的格式：算法/模式/填充模式
     * @param algorithm 算法
     * @param key 秘钥
     * @param params
     * @param mode {@link Cipher#ENCRYPT_MODE} or {@link Cipher#DECRYPT_MODE} or {@link Cipher#WRAP_MODE} or {@link Cipher#UNWRAP_MODE}
     * @return
     */
    public static byte[] cipher(byte[] data, String transformation, String algorithm, Key key, AlgorithmParameterSpec params, int mode){
        try {
            Cipher cipher = Cipher.getInstance(transformation != null ? transformation : algorithm);
            if(params != null){
                cipher.init(mode, key, params);
            }else{
                cipher.init(mode, key);
            }
            return cipher.doFinal(data);
        } catch (NoSuchAlgorithmException e) {
            e.printStackTrace();
        } catch (NoSuchPaddingException e) {
            e.printStackTrace();
        } catch (InvalidKeyException e) {
            e.printStackTrace();
        } catch (Exception e) {
            e.printStackTrace();
        }

        return null;
    }

    /**
     * 获取算法秘钥
     * @param key 秘钥
     * @param algorithm 算法
     * @return
     */
    private static Key obtainKey(byte[] key,String algorithm,int mode) {
        try {
            if (algorithm.equals(DES)) {// DES algorithm
                DESKeySpec desKey = new DESKeySpec(key);
                SecretKeyFactory keyFactory = SecretKeyFactory.getInstance(algorithm);
                return keyFactory.generateSecret(desKey);
            }
            if (algorithm.startsWith(DESede)) {// DESede algorithm
                DESedeKeySpec desEdeKey = new DESedeKeySpec(key);
                SecretKeyFactory keyFactory = SecretKeyFactory.getInstance(algorithm);
                return keyFactory.generateSecret(desEdeKey);
            }
            if(algorithm.equals(RSA)){// RSA algorithm
                if(mode == Cipher.DECRYPT_MODE){
                    return KeyFactory.getInstance(algorithm).generatePrivate(new PKCS8EncodedKeySpec(key));
                }
                return KeyFactory.getInstance(algorithm).generatePublic(new X509EncodedKeySpec(key));
            }
            return new SecretKeySpec(key,algorithm);
        }catch (Exception e){
            e.printStackTrace();
        }
        return null;
    }

}
