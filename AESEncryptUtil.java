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
 
            //TODO ���Դ���
            //String encodeStr = TypeConvert.bytesToHexString(encodeByte);
            return encodeByte;
        } else {
            byte[] decodeByte = encryptOrDecrypt(Cipher.DECRYPT_MODE, source, key, iv, type, encodeType);
 
            //TODO ���Դ���
            //String decodeStr = new String(decodeByte, CHARSET);
 
            return decodeByte;
        }
    }
 
 
    private static byte[] encryptOrDecrypt(int mode, byte[] byteContent, byte[] key, byte[] iv, AESType type, String modeAndPadding) throws InvalidKeyException, NoSuchAlgorithmException, InvalidAlgorithmParameterException, NoSuchPaddingException, BadPaddingException, IllegalBlockSizeException {
 
//        // *****  �����Ƿ����1,2,3,4 ���໹�����ɻ�
//        //1.������Կ��������ָ��ΪAES�㷨,�����ִ�Сд
//        KeyGenerator keygen=KeyGenerator.getInstance("AES");
//        //2.����ecnodeRules�����ʼ����Կ������
//        //����һ��ָ��λ�����Դ,���ݴ�����ֽ�����
//        keygen.init(type.getValue(), new SecureRandom(key));
//        //3.����ԭʼ�Գ���Կ
//        SecretKey secretKey=keygen.generateKey();
//        //4.���ԭʼ�Գ���Կ���ֽ�����
//        byte [] raw = secretKey.getEncoded();
 
       //5.�����ֽ���������AES��Կ
        SecretKey keySpec=new SecretKeySpec(key, "AES");
 
        //6.����ָ���㷨AES�Գ�������
        Cipher cipher = Cipher.getInstance(modeAndPadding);// ����������
 
        if (null != iv) {
            //ָ��һ����ʼ������ (Initialization vector��IV)�� IV ������16λ
            cipher.init(mode, keySpec, new IvParameterSpec(iv));
        } else {
            cipher.init(mode, keySpec);
        }
        byte[] result = cipher.doFinal(byteContent);
        return result;
    }
 
 
    /**
     * ָ��һ����ʼ������ (Initialization vector��IV)��IV ������16λ
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
