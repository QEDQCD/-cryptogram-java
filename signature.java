package crypto;

import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;

public class signature {
public static void main(String args[]){
    String signString="Thank you!";
    String type="SHA-1";
    String result=sign(signString,type);
    System.out.println("����"+type+"����֮��Ĵ�Ϊ��"+result);
    type="MD5";
    result=sign(signString,type);
    System.out.println("����"+type+"����֮��Ĵ�Ϊ��"+result);
    type="SHA-256";
    result=sign(signString,type);
    System.out.println("����"+type+"����֮��Ĵ�Ϊ��"+result);
    type="SHA-384";
    result=sign(signString,type);
    System.out.println("����"+type+"����֮��Ĵ�Ϊ��"+result);
}
    //ǩ��     
        public static String sign(String str, String type){
           String s=Encrypt(str,type);
            return s;
        }
        public static String Encrypt(String strSrc, String encName) {
            MessageDigest md = null;
            String strDes = null;
            byte[] bt = strSrc.getBytes();
            try {
                md = MessageDigest.getInstance(encName);
                md.update(bt);
                strDes = bytes2Hex(md.digest()); // to HexString
            } catch (NoSuchAlgorithmException e) {
                System.out.println("ǩ��ʧ�ܣ�");
                return null;
            }
            return strDes;
        }
        public static String bytes2Hex(byte[] bts) {
            String des = "";
            String tmp = null;
            for (int i = 0; i < bts.length; i++) {
                tmp = (Integer.toHexString(bts[i] & 0xFF));
                if (tmp.length() == 1) {
                    des += "0";
                }
                des += tmp;
            }
            return des;
        }
}
