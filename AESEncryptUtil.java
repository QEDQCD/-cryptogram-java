package crypto;
 
import javax.crypto.*;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import java.io.UnsupportedEncodingException;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.util.Base64;
import java.util.*;
 

public class AESEncryptUtil {
 
    public static final String CHARSET = "UTF-8";
 
    /**
     * @param isEncrypt
     * @param source
     * @param key
     * @param iv
     * @param type
     * @param encodeType
     * @return
     * @throws UnsupportedEncodingException
     * @throws InvalidAlgorithmParameterException
     * @throws NoSuchAlgorithmException
     * @throws NoSuchPaddingException
     * @throws BadPaddingException
     * @throws IllegalBlockSizeException
     * @throws InvalidKeyException
     */
    public static byte[] encryptOrDecrypt(boolean isEncrypt, byte[] source, byte[] key, byte[] iv, AESType type, String encodeType) throws UnsupportedEncodingException, InvalidAlgorithmParameterException, NoSuchAlgorithmException, NoSuchPaddingException, BadPaddingException, IllegalBlockSizeException, InvalidKeyException {
        if (isEncrypt) {
            byte[] encodeByte = encryptOrDecrypt(Cipher.ENCRYPT_MODE, source, key, iv, type, encodeType);
 
            //TODO 测试代码
            //String encodeStr = TypeConvert.bytesToHexString(encodeByte);
            return encodeByte;
        } else {
            byte[] decodeByte = encryptOrDecrypt(Cipher.DECRYPT_MODE, source, key, iv, type, encodeType);
 
            //TODO 测试代码
            //String decodeStr = new String(decodeByte, CHARSET);
 
            return decodeByte;
        }
    }
 
 
    private static byte[] encryptOrDecrypt(int mode, byte[] byteContent, byte[] key, byte[] iv, AESType type, String modeAndPadding) throws InvalidKeyException, NoSuchAlgorithmException, InvalidAlgorithmParameterException, NoSuchPaddingException, BadPaddingException, IllegalBlockSizeException {
 
//        // *****  对于是否存在1,2,3,4 步奏还存在疑惑
//        //1.构造密钥生成器，指定为AES算法,不区分大小写
//        KeyGenerator keygen=KeyGenerator.getInstance("AES");
//        //2.根据ecnodeRules规则初始化密钥生成器
//        //生成一个指定位的随机源,根据传入的字节数组
//        keygen.init(type.getValue(), new SecureRandom(key));
//        //3.产生原始对称密钥
//        SecretKey secretKey=keygen.generateKey();
//        //4.获得原始对称密钥的字节数组
//        byte [] raw = secretKey.getEncoded();
 
       //5.根据字节数组生成AES密钥
        SecretKey keySpec=new SecretKeySpec(key, "AES");
 
        //6.根据指定算法AES自成密码器
        Cipher cipher = Cipher.getInstance(modeAndPadding);// 创建密码器
 
        if (null != iv) {
            //指定一个初始化向量 (Initialization vector，IV)， IV 必须是16位
            cipher.init(mode, keySpec, new IvParameterSpec(iv));
        } else {
            cipher.init(mode, keySpec);
        }
        byte[] result = cipher.doFinal(byteContent);
        return result;
    }
 
 
    /**
     * 指定一个初始化向量 (Initialization vector，IV)，IV 必须是16位
     */
    public static final byte[] getIV() throws Exception {
        return "1234567812345678".getBytes(CHARSET);
    }
 
 
    public static void main(String[] args) throws Exception {
 

 
 
 
        String content = "56.2";
        String key = "91efa40df1a5e576";
        byte[] encrypt = encryptOrDecrypt(true, content.getBytes("utf-8"), key.getBytes("utf-8"), null, AESType.AES_128, EncodeType.AES_ECB_PKCS5Padding);
        //String line = Base64EncryptUtil.safeUrlBase64Encode(encrypt);
        String line = Base64.encodeBase64URLSafeString(encrypt);
        System.out.println(line);
 

 
    }
 
 
}
