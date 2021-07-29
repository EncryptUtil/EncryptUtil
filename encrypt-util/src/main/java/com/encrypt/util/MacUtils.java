package com.encrypt.util;

import javax.crypto.Mac;
import javax.crypto.spec.SecretKeySpec;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.Key;
import java.security.NoSuchAlgorithmException;
import java.security.spec.AlgorithmParameterSpec;

/**
 * {@link Mac}
 * @see <a href="https://docs.oracle.com/javase/8/docs/technotes/guides/security/StandardNames.html#Mac">Standard Algorithm Name Documentation</a>
 * @author <a href="mailto:jenly1314@gmail.com">Jenly</a>
 */
public final class MacUtils {

    //-------------------- algorithm --------------------//
    public static final String HmacMD5 = "HmacMD5";
    public static final String HmacSHA1 = "HmacSHA1";
    public static final String HmacSHA224 = "HmacSHA224";
    public static final String HmacSHA256 = "HmacSHA256";
    public static final String HmacSHA384 = "HmacSHA384";
    public static final String HmacSHA512 = "HmacSHA512";

    private MacUtils(){

    }

    /**
     * HmacMD5 加密
     * @param data 需加密的数据
     * @param key 秘钥
     * @return
     */
    public static byte[] hMacMd5(byte[] data,byte[] key){
        return encrypt(data,HmacMD5,key);
    }

    /**
     * HmacMD5 加密
     * @param data 需加密的数据
     * @param key 秘钥
     * @return
     */
    public static String hMacMd5(String data,byte[] key){
        return encryptToHexString(data,HmacMD5,key);
    }

    /**
     * HmacSHA1 加密
     * @param data 需加密的数据
     * @param key 秘钥
     * @return
     */
    public static byte[] hMacSha1(byte[] data,byte[] key){
        return encrypt(data,HmacSHA1,key);
    }

    /**
     * HmacSHA1 加密
     * @param data 需加密的数据
     * @param key 秘钥
     * @return
     */
    public static String hMacSha1(String data,byte[] key){
        return encryptToHexString(data,HmacSHA1,key);
    }

    /**
     * HmacSHA224 加密
     * @param data 需加密的数据
     * @param key 秘钥
     * @return
     */
    public static byte[] hMacSha224(byte[] data,byte[] key){
        return encrypt(data,HmacSHA224,key);
    }

    /**
     * HmacSHA224 加密
     * @param data 需加密的数据
     * @param key 秘钥
     * @return
     */
    public static String hMacSha224(String data,byte[] key){
        return encryptToHexString(data,HmacSHA224,key);
    }

    /**
     * HmacSHA256 加密
     * @param data 需加密的数据
     * @param key 秘钥
     * @return
     */
    public static byte[] hMacSha256(byte[] data,byte[] key){
        return encrypt(data,HmacSHA256,key);
    }

    /**
     * HmacSHA256 加密
     * @param data 需加密的数据
     * @param key 秘钥
     * @return
     */
    public static String hMacSha256(String data,byte[] key){
        return encryptToHexString(data,HmacSHA256,key);
    }

    /**
     * HmacSHA384 加密
     * @param data 需加密的数据
     * @param key 秘钥
     * @return
     */
    public static byte[] hMacSha384(byte[] data,byte[] key){
        return encrypt(data,HmacSHA384,key);
    }

    /**
     * HmacSHA384 加密
     * @param data 需加密的数据
     * @param key 秘钥
     * @return
     */
    public static String hMacSha384(String data,byte[] key){
        return encryptToHexString(data,HmacSHA384,key);
    }

    /**
     * HmacSHA512 加密
     * @param data 需加密的数据
     * @param key 秘钥
     * @return
     */
    public static byte[] hMacSha512(byte[] data,byte[] key){
        return encrypt(data,HmacSHA512,key);
    }

    /**
     * HmacSHA512 加密
     * @param data 需加密的数据
     * @param key 秘钥
     * @return
     */
    public static String hMacSha512(String data,byte[] key){
        return encryptToHexString(data,HmacSHA512,key);
    }

    /**
     * 加密
     * @param data 需加密的数据
     * @param algorithm 算法
     * @param key 秘钥
     * @return
     */
    public static String encryptToHexString(String data, String algorithm, byte[] key){
        byte[] result = encrypt(data.getBytes(),algorithm,key);
        if(result != null){
            return HexUtils.byteArrayToHexString(result);
        }
        return null;
    }

    /**
     * 加密
     * @param data 需加密的数据
     * @param algorithm 算法
     * @param key 秘钥
     * @return
     */
    public static byte[] encrypt(byte[] data, String algorithm, byte[] key){
        return encrypt(data,algorithm,key,null);
    }

    /**
     * 加密
     * @param data 需加密的数据
     * @param algorithm 算法
     * @param key 秘钥
     * @param params 算法参数
     * @return
     */
    public static byte[] encrypt(byte[] data, String algorithm, byte[] key, AlgorithmParameterSpec params){
        SecretKeySpec secretKey = new SecretKeySpec(key,algorithm);
        return encrypt(data,algorithm,secretKey,params);
    }

    /**
     * 加密
     * @param data 需加密的数据
     * @param algorithm 算法
     * @param key 秘钥
     * @param params 算法参数 
     * @return
     */
    public static byte[] encrypt(byte[] data, String algorithm, Key key, AlgorithmParameterSpec params){
        try {
            Mac mac = Mac.getInstance(algorithm);
            mac.init(key,params);
            return mac.doFinal(data);
        } catch (NoSuchAlgorithmException e) {
            e.printStackTrace();
        } catch (InvalidKeyException e) {
            e.printStackTrace();
        } catch (InvalidAlgorithmParameterException e) {
            e.printStackTrace();
        }catch (Exception e){
            e.printStackTrace();
        }
        return null;
    }

}
