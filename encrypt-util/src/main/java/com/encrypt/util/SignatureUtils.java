package com.encrypt.util;

import java.security.*;
import java.security.cert.Certificate;
import java.security.spec.AlgorithmParameterSpec;

/**
 * {@link Signature}
 * @see <a href="https://docs.oracle.com/javase/8/docs/technotes/guides/security/StandardNames.html#Signature">Standard Algorithm Name Documentation</a>
 * @author <a href="mailto:jenly1314@gmail.com">Jenly</a>
 */
public class SignatureUtils {

    //-------------------- algorithm --------------------//
    public static final String NONEwithRSA = "NONEwithRSA";
    public static final String MD2withRSA = "MD2withRSA";
    public static final String MD5withRSA = "MD5withRSA";
    public static final String SHA1withRSA = "SHA1withRSA";
    public static final String SHA224withRSA = "SHA224withRSA";
    public static final String SHA256withRSA = "SHA256withRSA";
    public static final String SHA384withRSA = "SHA384withRSA";
    public static final String SHA512withRSA = "SHA512withRSA";
    public static final String SHA512_224withRSA = "SHA512/224withRSA";
    public static final String SHA512_256withRSA = "SHA512/256withRSA";
    public static final String RSASSA_PSS = "RSASSA-PSS";
    public static final String NONEwithDSA = "NONEwithDSA";
    public static final String SHA1withDSA = "SHA1withDSA";
    public static final String SHA224withDSA = "SHA224withDSA";
    public static final String SHA256withDSA = "SHA256withDSA";
    public static final String SHA384withDSA = "SHA384withDSA";
    public static final String SHA512withDSA = "SHA512withDSA";
    public static final String NONEwithECDSA = "NONEwithECDSA";
    public static final String SHA1withECDSA = "SHA1withECDSA";
    public static final String SHA224withECDSA = "SHA224withECDSA";
    public static final String SHA256withECDSA = "SHA256withECDSA";
    public static final String SHA384withECDSA = "SHA384withECDSA";
    public static final String SHA512withECDSA = "SHA512withECDSA";

    private SignatureUtils(){

    }

    /**
     * 校验签名
     * @param data 未签名的数据
     * @param signatureData 需验证的签名数据
     * @param algorithm 算法
     * @param certificate
     * @return
     */
    public static boolean verify(byte[] data, byte[] signatureData, String algorithm, Certificate certificate){
        return verify(data,signatureData,algorithm,certificate,null);
    }

    /**
     * 校验签名
     * @param data 未签名的数据
     * @param signatureData 需验证的签名数据
     * @param algorithm 算法
     * @param certificate
     * @param params 算法参数
     * @return
     */
    public static boolean verify(byte[] data, byte[] signatureData, String algorithm, Certificate certificate,
                                 AlgorithmParameterSpec params){
        try {
            Signature signature = Signature.getInstance(algorithm);
            signature.initVerify(certificate);
            if(params != null){
                signature.setParameter(params);
            }
            signature.update(data);
            return signature.verify(signatureData);
        } catch (NoSuchAlgorithmException e) {
            e.printStackTrace();
        } catch (InvalidKeyException e) {
            e.printStackTrace();
        } catch (InvalidAlgorithmParameterException e) {
            e.printStackTrace();
        } catch (SignatureException e) {
            e.printStackTrace();
        }catch (Exception e){
            e.printStackTrace();
        }
        return false;
    }

    /**
     * 校验签名
     * @param data 未签名的数据
     * @param signatureData 需验证的签名数据
     * @param algorithm 算法
     * @param publicKey 公钥
     * @return
     */
    public static boolean verify(byte[] data, byte[] signatureData, String algorithm, PublicKey publicKey){
        return verify(data,signatureData,algorithm,publicKey,null);
    }

    /**
     * 校验签名
     * @param data 未签名的数据
     * @param signatureData 需验证的签名数据
     * @param algorithm 算法
     * @param publicKey 公钥
     * @param params 算法参数
     * @return
     */
    public static boolean verify(byte[] data, byte[] signatureData, String algorithm, PublicKey publicKey,
                                 AlgorithmParameterSpec params){
        try {
            Signature signature = Signature.getInstance(algorithm);
            signature.initVerify(publicKey);
            if(params != null){
                signature.setParameter(params);
            }
            signature.update(data);
            return signature.verify(signatureData);
        } catch (NoSuchAlgorithmException e) {
            e.printStackTrace();
        } catch (InvalidKeyException e) {
            e.printStackTrace();
        } catch (InvalidAlgorithmParameterException e) {
            e.printStackTrace();
        } catch (SignatureException e) {
            e.printStackTrace();
        }catch (Exception e){
            e.printStackTrace();
        }
        return false;
    }

    /**
     * 签名
     * @param data 未签名的数据
     * @param algorithm 算法
     * @param privateKey
     * @return
     */
    public static byte[] sign(byte[] data, String algorithm, PrivateKey privateKey){
        return sign(data,algorithm,privateKey,null,null);
    }

    /**
     * 签名
     * @param data 未签名的数据
     * @param algorithm 算法
     * @param privateKey
     * @param params 算法参数
     * @param random
     * @return
     */
    public static byte[] sign(byte[] data, String algorithm, PrivateKey privateKey,
                              AlgorithmParameterSpec params, SecureRandom random){
        try {
            Signature signature = Signature.getInstance(algorithm);
            signature.initSign(privateKey,random);
            if(params != null){
                signature.setParameter(params);
            }
            signature.update(data);
            return signature.sign();
        } catch (NoSuchAlgorithmException e) {
            e.printStackTrace();
        } catch (SignatureException e) {
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
