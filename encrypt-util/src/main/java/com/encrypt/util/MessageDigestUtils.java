package com.encrypt.util;

import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;

/**
 * {@link MessageDigest}
 * @see <a href="https://docs.oracle.com/javase/8/docs/technotes/guides/security/StandardNames.html#MessageDigest">Standard Algorithm Name Documentation</a>
 * @author <a href="mailto:jenly1314@gmail.com">Jenly</a>
 */
public final class MessageDigestUtils {

    private static final String MD2 = "MD2";
    private static final String MD5 = "MD5";
    private static final String SHA1 = "SHA-1";
    private static final String SHA224 = "SHA-224";
    private static final String SHA256 = "SHA-256";
    private static final String SHA384 = "SHA-384";
    private static final String SHA512 = "SHA-512";
    private static final String SHA512_224 = "SHA-512/224";
    private static final String SHA512_256 = "SHA-512/256";

    private MessageDigestUtils(){

    }

    /**
     * MD2 加密
     * @param data 需加密的数据
     * @return
     */
    public static byte[] md2(byte[] data){
        return encrypt(data, MD2);
    }

    /**
     * MD2 加密
     * @param data 需加密的数据
     * @return
     */
    public static String md2(String data){
        return encryptToHexString(data, MD2);
    }

    /**
     * MD5 加密
     * @param data 需加密的数据
     * @return
     */
    public static byte[] md5(byte[] data){
        return encrypt(data, MD5);
    }

    /**
     * MD5 加密
     * @param data 需加密的数据
     * @return
     */
    public static String md5(String data){
        return encryptToHexString(data, MD5);
    }

    /**
     * SHA1 加密
     * @param data 需加密的数据
     * @return
     */
    public static byte[] sha1(byte[] data){
        return encrypt(data, SHA1);
    }

    /**
     * SHA1 加密
     * @param data 需加密的数据
     * @return
     */
    public static String sha1(String data){
        return encryptToHexString(data, SHA1);
    }

    /**
     * SHA224 加密
     * @param data 需加密的数据
     * @return
     */
    public static byte[] sha224(byte[] data){
        return encrypt(data, SHA224);
    }

    /**
     * SHA224 加密
     * @param data 需加密的数据
     * @return
     */
    public static String sha224(String data){
        return encryptToHexString(data, SHA224);
    }


    /**
     * SHA256 加密
     * @param data 需加密的数据
     * @return
     */
    public static byte[] sha256(byte[] data){
        return encrypt(data, SHA256);
    }

    /**
     * SHA256 加密
     * @param data 需加密的数据
     * @return
     */
    public static String sha256(String data){
        return encryptToHexString(data, SHA256);
    }

    /**
     * SHA384 加密
     * @param data 需加密的数据
     * @return
     */
    public static byte[] sha384(byte[] data){
        return encrypt(data, SHA384);
    }

    /**
     * SHA384 加密
     * @param data 需加密的数据
     * @return
     */
    public static String sha384(String data){
        return encryptToHexString(data, SHA384);
    }

    /**
     * SHA512 加密
     * @param data 需加密的数据
     * @return
     */
    public static byte[] sha512(byte[] data){
        return encrypt(data, SHA512);
    }

    /**
     * SHA512 加密
     * @param data 需加密的数据
     * @return
     */
    public static String sha512(String data){
        return  encryptToHexString(data, SHA512);
    }

    /**
     * SHA512/224 加密
     * @param data 需加密的数据
     * @return
     */
    public static byte[] sha512_224(byte[] data){
        return encrypt(data, SHA512_224);
    }

    /**
     * SHA512/224 加密
     * @param data 需加密的数据
     * @return
     */
    public static String sha512_224(String data){
        return encryptToHexString(data, SHA512_224);
    }
    /**
     * SHA512/256 加密
     * @param data 需加密的数据
     * @return
     */
    public static byte[] sha512_256(byte[] data){
        return encrypt(data, SHA512_256);
    }
    /**
     * SHA512/256 加密
     * @param data 需加密的数据
     * @return
     */
    public static String sha512_256(String data){
        return encryptToHexString(data, SHA512_256);
    }
    /**
     * 加密
     * @param data 需加密的数据
     * @param algorithm 算法
     * @return
     */
    private static String encryptToHexString(String data, String algorithm)  {
        byte[] result = encrypt(data.getBytes(), algorithm);
        if(result != null){
            return HexUtils.byteArrayToHexString(result);
        }
        return null;
    }

    /**
     * 加密
     * @param data 需加密的数据
     * @param algorithm 算法
     * @return
     */
    private static byte[] encrypt(byte[] data, String algorithm)  {
        try {
            MessageDigest digest = MessageDigest.getInstance(algorithm);
            digest.update(data);
            return digest.digest();
        } catch (NoSuchAlgorithmException e) {
            e.printStackTrace();
        } catch (Exception e){
            e.printStackTrace();
        }
        return null;
    }


}
