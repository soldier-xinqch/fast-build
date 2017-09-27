package com.fast.build.util;

import javax.crypto.*;
import javax.crypto.spec.DESKeySpec;
import javax.crypto.spec.SecretKeySpec;
import java.io.*;
import java.math.BigInteger;
import java.security.*;
import java.security.interfaces.RSAPrivateKey;
import java.security.interfaces.RSAPublicKey;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.RSAPrivateCrtKeySpec;
import java.security.spec.RSAPublicKeySpec;
import java.security.spec.X509EncodedKeySpec;
import java.util.Arrays;
import java.util.Base64;

/**
 *  加密解密工具类
 * Created by xinch on 2017/9/27.
 */
public class EncryptAndDecodeUtils {

    private static final char[] HEXES = {
            '0', '1', '2', '3','4', '5', '6', '7','8', '9',
            'a', 'b','c', 'd', 'e', 'f','g','h','i','j','k','l','m','n','o','p','q','r','s','t','u','v','w','x','y','z'
    };

    /** 指定key的大小 */
    private static int KEYSIZE = 1024;
    /** 指定公钥存放文件 */
    private static String PUBLIC_KEY_FILE = "public.keystore";
    /** 指定私钥存放文件 */
    private static String PRIVATE_KEY_FILE = "private.keystore";

    /**
     *  base64 编码
     * @param encryptStr
     * @return
     * @throws UnsupportedEncodingException
     */
    public static String encryptBase64(String encryptStr) throws UnsupportedEncodingException {
        return Base64.getEncoder().encodeToString(encryptStr.getBytes("utf-8"));
    }

    /**
     *  base64 解码
     * @param dencryptStr
     * @return
     * @throws UnsupportedEncodingException
     */
    public static String dencryptBase64(String dencryptStr) throws UnsupportedEncodingException {
        byte[] asBytes = Base64.getDecoder().decode(dencryptStr);
        return new String(asBytes, "utf-8");
    }






    /**
     * 使用JDK实现MD5加密
     * @param md5Str：消息
     */
    public static String getPassMD5(String md5Str) {
        String keys = null;
        try {
            MessageDigest md = MessageDigest.getInstance("MD5");
            if (md5Str == null) {
                md5Str = "";
            }
            byte[] bPass = md5Str.getBytes("UTF-8");
            //	byte[] bPass = pass.getBytes();  j7 默认编码是u8   而j8不是，所以这个时候，中文加密有问题，j7与j8加密出来的密文不想等，J7是对的
            System.out.println(Arrays.toString(bPass));
            md.update(bPass);
            // keys = new String(md.digest(), "GBK");
            keys = bytesToHexString(md.digest());
        } catch (Exception aex) {
            aex.printStackTrace();
        }
        return keys;
    }

    /**
     * 将beye[]转换为十六进制字符串
     *
     * @param bArray
     * @return
     */
    public static final String bytesToHexString(byte[] bArray) {
        System.out.println(Arrays.toString(bArray));
        StringBuffer sb = new StringBuffer(bArray.length);
        String sTemp;
        for (int i = 0; i < bArray.length; i++) {
            sTemp = Integer.toHexString(0xFF & bArray[i]);
            if (sTemp.length() < 2) {
                sb.append(0);
            }
            sb.append(sTemp.toUpperCase());
        }
        return sb.toString().toLowerCase();
    }










    /**
     * 根据指定的算法加密任意长度的数据, 返回固定长度的十六进制小写哈希值
     *
     * @param data 需要加密的数据
     * @param algorithm 加密算法, 例如: MD5, SHA-1, SHA-256, SHA-512 等
     */
    public static String encryptStrAlgorithm(byte[] data, ALGORITHMTYPE algorithm) throws Exception {
        // 1. 根据算法名称获实现了算法的加密实例
        MessageDigest digest = MessageDigest.getInstance(algorithm.getValue());

        // 2. 加密数据, 计算数据的哈希值
        byte[] cipher = digest.digest(data);

        // 3. 将结果转换为十六进制小写
        return bytes2Hex(cipher);
    }

    public static String bytes2Hex(byte[] bytes) {
        if (bytes == null || bytes.length == 0) {
            return null;
        }
        StringBuilder sb = new StringBuilder();
        for (byte b : bytes) {
            sb.append(HEXES[(b >> 4) & 0x0F]);
            sb.append(HEXES[b & 0x0F]);
        }
        return sb.toString();
    }


    /**
     * 根据指定的算法加密文件数据, 返回固定长度的十六进制小写哈希值
     *
     * @param file 需要加密的文件
     * @param algorithm 加密算法, 例如: MD5, SHA-1, SHA-256, SHA-512 等
     */
    public static String encryptFileAlgorithm(File file, ALGORITHMTYPE algorithm) throws Exception {
        InputStream in = null;

        try {
            // 1. 根据算法名称获实现了算法的加密实例
            MessageDigest digest = MessageDigest.getInstance(algorithm.getValue());

            in = new FileInputStream(file);
            byte[] buf = new byte[1024];
            int len = -1;
            while ((len = in.read(buf)) != -1) {
                // 2. 文件数据通常比较大, 使用 update() 方法逐步添加
                digest.update(buf, 0, len);
            }
            // 3. 计算数据的哈希值, 添加完数据后 digest() 方法只能被调用一次
            byte[] cipher = digest.digest();
            // 4. 将结果转换为十六进制小写
            return bytes2Hex(cipher);
        } finally {
            if (in != null) {
                try {
                    in.close();
                } catch (Exception e) {
                    // nothing
                }
            }
        }
    }












    /**
     * 加密数据
     * @param data  待加密数据
     * @param key  密钥
     * @return 加密后的数据
     */
    public static String encryptDes(String data, String key) throws Exception {
        Key deskey = keyGenerator(key);
        // 实例化Cipher对象，它用于完成实际的加密操作
        Cipher cipher = Cipher.getInstance(ALGORITHMTYPE.DES.getValue());
        SecureRandom random = new SecureRandom();
        // 初始化Cipher对象，设置为加密模式
        cipher.init(Cipher.ENCRYPT_MODE, deskey, random);
        byte[] results = cipher.doFinal(data.getBytes());
        // 该部分是为了与加解密在线测试网站（http://tripledes.online-domain-tools.com/）的十六进制结果进行核对
        for (int i = 0; i < results.length; i++) {
            System.out.print(results[i] + " ");
        }
        System.out.println();
        // 执行加密操作。加密后的结果通常都会用Base64编码进行传输
        return Base64.getEncoder().encodeToString(results);
    }

    /**
     * 解密数据
     *
     * @param data  待解密数据
     * @param key  密钥
     * @return 解密后的数据
     */
    public static String decryptDes(String data, String key) throws Exception {
        Key deskey = keyGenerator(key);
        Cipher cipher = Cipher.getInstance(ALGORITHMTYPE.DES.getValue());
        // 初始化Cipher对象，设置为解密模式
        cipher.init(Cipher.DECRYPT_MODE, deskey);
        // 执行解密操作
        return new String(cipher.doFinal(Base64.getDecoder().decode(data)));
    }
    /**
     *
     * 生成密钥key对象
     *
     * @param keyStr  密钥字符串
     * @return 密钥对象
     * @throws Exception
     */
    private static SecretKey keyGenerator(String keyStr) throws Exception {
        byte input[] = HexString2Bytes(keyStr);
        DESKeySpec desKey = new DESKeySpec(input);
        // 创建一个密匙工厂，然后用它把DESKeySpec转换成
        SecretKeyFactory keyFactory = SecretKeyFactory.getInstance("DES");
        SecretKey securekey = keyFactory.generateSecret(desKey);
        return securekey;
    }

    private static int parse(char c) {
        if (c >= 'a')
            return (c - 'a' + 10) & 0x0f;
        if (c >= 'A')
            return (c - 'A' + 10) & 0x0f;
        return (c - '0') & 0x0f;
    }

    // 从十六进制字符串到字节数组转换
    public static byte[] HexString2Bytes(String hexstr) {
        byte[] b = new byte[hexstr.length() / 2];
        int j = 0;
        for (int i = 0; i < b.length; i++) {
            char c0 = hexstr.charAt(j++);
            char c1 = hexstr.charAt(j++);
            b[i] = (byte) ((parse(c0) << 4) | parse(c1));
        }
        return b;
    }














    /**
     * 生成密钥对
     */
    private static void generateKeyPair() throws Exception {
        /** RSA算法要求有一个可信任的随机数源 */
        SecureRandom sr = new SecureRandom();
        /** 为RSA算法创建一个KeyPairGenerator对象 */
        KeyPairGenerator kpg = KeyPairGenerator.getInstance(ALGORITHMTYPE.RSA.getValue());
        /** 利用上面的随机数据源初始化这个KeyPairGenerator对象 */
        kpg.initialize(KEYSIZE, sr);
        /** 生成密匙对 */
        KeyPair kp = kpg.generateKeyPair();
        /** 得到公钥 */
        Key publicKey = kp.getPublic();
        /** 得到私钥 */
        Key privateKey = kp.getPrivate();
        /** 用对象流将生成的密钥写入文件 */
        ObjectOutputStream oos1 = new ObjectOutputStream(new FileOutputStream(PUBLIC_KEY_FILE));
        ObjectOutputStream oos2 = new ObjectOutputStream(new FileOutputStream(PRIVATE_KEY_FILE));
        oos1.writeObject(publicKey);
        oos2.writeObject(privateKey);
        /** 清空缓存，关闭文件输出流 */
        oos1.close();
        oos2.close();
    }

    /**
     * 生成密钥对字符串
     */
    private static void generateKeyPairString() throws Exception {
        /** RSA算法要求有一个可信任的随机数源 */
        SecureRandom sr = new SecureRandom();
        /** 为RSA算法创建一个KeyPairGenerator对象 */
        KeyPairGenerator kpg = KeyPairGenerator.getInstance(ALGORITHMTYPE.RSA.getValue());
        /** 利用上面的随机数据源初始化这个KeyPairGenerator对象 */
        kpg.initialize(KEYSIZE, sr);
        /** 生成密匙对 */
        KeyPair kp = kpg.generateKeyPair();
        /** 得到公钥 */
        Key publicKey = kp.getPublic();
        /** 得到私钥 */
        Key privateKey = kp.getPrivate();
        /** 用字符串将生成的密钥写入文件 */

        String algorithm = publicKey.getAlgorithm(); // 获取算法
        KeyFactory keyFact = KeyFactory.getInstance(algorithm);
        BigInteger prime = null;
        BigInteger exponent = null;

        RSAPublicKeySpec keySpec = (RSAPublicKeySpec) keyFact.getKeySpec(publicKey, RSAPublicKeySpec.class);

        prime = keySpec.getModulus();
        exponent = keySpec.getPublicExponent();
        System.out.println(privateKey.getAlgorithm());
        RSAPrivateCrtKeySpec privateKeySpec = (RSAPrivateCrtKeySpec) keyFact.getKeySpec(privateKey,
                RSAPrivateCrtKeySpec.class);
        BigInteger privateModulus = privateKeySpec.getModulus();
        BigInteger privateExponent = privateKeySpec.getPrivateExponent();

    }

    /**
     * 加密方法 source： 源数据
     */
    public static String encrypt(String source) throws Exception {
        generateKeyPair();
        /** 将文件中的公钥对象读出 */
        ObjectInputStream ois = new ObjectInputStream(new FileInputStream(PUBLIC_KEY_FILE));
        Key key = (Key) ois.readObject();
        ois.close();

        String algorithm = key.getAlgorithm(); // 获取算法
        KeyFactory keyFact = KeyFactory.getInstance(algorithm);
        BigInteger prime = null;
        BigInteger exponent = null;
        if ("RSA".equals(algorithm)) { // 如果是RSA加密
            RSAPublicKeySpec keySpec = (RSAPublicKeySpec) keyFact.getKeySpec(key, RSAPublicKeySpec.class);
            prime = keySpec.getModulus();
            exponent = keySpec.getPublicExponent();
        }

        /** 得到Cipher对象来实现对源数据的RSA加密 */
        Cipher cipher = Cipher.getInstance(ALGORITHMTYPE.RSA.getValue());
        cipher.init(Cipher.ENCRYPT_MODE, key);
        byte[] b = source.getBytes();
        /** 执行加密操作 */
        byte[] b1 = cipher.doFinal(b);
        return Base64.getEncoder().encodeToString(b1);
    }

    /**
     * 解密算法 cryptograph:密文
     */
    public static String decrypt(String cryptograph) throws Exception {
        /** 将文件中的私钥对象读出 */
        ObjectInputStream ois = new ObjectInputStream(new FileInputStream(PRIVATE_KEY_FILE));
        Key key = (Key) ois.readObject();

        String algorithm = key.getAlgorithm(); // 获取算法
        KeyFactory keyFact = KeyFactory.getInstance(algorithm);
        RSAPrivateCrtKeySpec privateKeySpec = (RSAPrivateCrtKeySpec) keyFact.getKeySpec(key,
                RSAPrivateCrtKeySpec.class);
        BigInteger privateModulus = privateKeySpec.getModulus();
        BigInteger privateExponent = privateKeySpec.getPrivateExponent();

        /** 得到Cipher对象对已用公钥加密的数据进行RSA解密 */
        Cipher cipher = Cipher.getInstance(ALGORITHMTYPE.RSA.getValue());
        cipher.init(Cipher.DECRYPT_MODE, key);

        byte[] b1 = Base64.getDecoder().decode(cryptograph);
        /** 执行解密操作 */
        byte[] b = cipher.doFinal(b1);
        return new String(b,"UTF-8");
    }















    /**
     * 说明： 用java的jdk里面相关方法实现rsa的签名及签名验证
     */
    public static void jdkRSA(String signStr) {
        try {
            // 1.初始化密钥
            KeyPairGenerator keyPairGenerator = KeyPairGenerator
                    .getInstance(ALGORITHMTYPE.RSA.getValue());
            //设置KEY的长度
            keyPairGenerator.initialize(512);
            KeyPair keyPair = keyPairGenerator.generateKeyPair();
            //得到公钥
            RSAPublicKey rsaPublicKey = (RSAPublicKey) keyPair.getPublic();
            //得到私钥
            RSAPrivateKey rsaPrivateKey = (RSAPrivateKey) keyPair.getPrivate();

            // 2.进行签名
            //用私钥进行签名
            PKCS8EncodedKeySpec pkcs8EncodedKeySpec = new PKCS8EncodedKeySpec(
                    rsaPrivateKey.getEncoded());
            KeyFactory keyFactory = KeyFactory.getInstance(ALGORITHMTYPE.RSA.getValue());
            //构造一个privateKey
            PrivateKey privateKey = keyFactory
                    .generatePrivate(pkcs8EncodedKeySpec);
            //声明签名的对象
            Signature signature = Signature.getInstance("MD5withRSA");
            signature.initSign(privateKey);
            signature.update(signStr.getBytes());
            //进行签名
            byte[] result = signature.sign();
//            System.out.println("jdk rsa sign:" + Hex.encodeHexString(result));

            // 3.验证签名
            //用公钥进行验证签名
            X509EncodedKeySpec x509EncodedKeySpec = new X509EncodedKeySpec(
                    rsaPublicKey.getEncoded());
            keyFactory = KeyFactory.getInstance("RSA");
            //构造一个publicKey
            PublicKey publicKey = keyFactory.generatePublic(x509EncodedKeySpec);
            //声明签名对象
            signature = Signature.getInstance("MD5withRSA");
            signature.initVerify(publicKey);
            signature.update(signStr.getBytes());
            //验证签名
            boolean bool = signature.verify(result);
            System.out.println("jdk rsa verify:" + bool);
        } catch (Exception e) {
            System.out.println(e.toString());
        }

    }






    /**
     * AES加密
     * @param content
     * @param password
     * @return
     */
    private static byte[] encrypt(byte[] content, String password) {
        try {
            KeyGenerator kgen = KeyGenerator.getInstance(ALGORITHMTYPE.AES.getValue());
            SecureRandom random=SecureRandom.getInstance("SHA1PRNG");
            random.setSeed(password.getBytes());
            kgen.init(128,random);
            SecretKey secretKey = kgen.generateKey();
            byte[] enCodeFormat = secretKey.getEncoded();
            SecretKeySpec key = new SecretKeySpec(enCodeFormat, ALGORITHMTYPE.AES.getValue());
            Cipher cipher = Cipher.getInstance("AES");// 创建密码器
            cipher.init(Cipher.ENCRYPT_MODE, key);// 初始化
            byte[] result = cipher.doFinal(content);
            return result; // 加密
        } catch (NoSuchAlgorithmException e) {
            e.printStackTrace();
        } catch (NoSuchPaddingException e) {
            e.printStackTrace();
        } catch (InvalidKeyException e) {
            e.printStackTrace();
        } catch (IllegalBlockSizeException e) {
            e.printStackTrace();
        } catch (BadPaddingException e) {
            e.printStackTrace();
        }
        return null;
    }

    /**
     * AES解密
     * @param content
     * @param password
     * @return
     */
    private static byte[] decrypt(byte[] content, String password) {
        try {
            KeyGenerator kgen = KeyGenerator.getInstance("AES");
            SecureRandom random=SecureRandom.getInstance("SHA1PRNG");
            random.setSeed(password.getBytes());
            kgen.init(128,random);
            SecretKey secretKey = kgen.generateKey();
            byte[] enCodeFormat = secretKey.getEncoded();
            SecretKeySpec key = new SecretKeySpec(enCodeFormat, "AES");
            Cipher cipher = Cipher.getInstance("AES");// 创建密码器
            cipher.init(Cipher.DECRYPT_MODE, key);// 初始化
            byte[] result = cipher.doFinal(content);
            return result; // 加密
        } catch (NoSuchAlgorithmException e) {
            e.printStackTrace();
        } catch (NoSuchPaddingException e) {
            e.printStackTrace();
        } catch (InvalidKeyException e) {
            e.printStackTrace();
        } catch (IllegalBlockSizeException e) {
            e.printStackTrace();
        } catch (BadPaddingException e) {
            e.printStackTrace();
        }
        return null;
    }


    enum  ALGORITHMTYPE {
        MD5("md5"),
        DES("DES"),// DES共有四种工作模式-->>ECB：电子密码本模式、CBC：加密分组链接模式、CFB：加密反馈模式、OFB：输出反馈模式
        RSA("RSA"),
        AES("AES"),
        SHA_1("SHA-1"),
        SHA_256("SHA-256"),
        SHA_512("SHA-512")
        ;

        private final String value;

        ALGORITHMTYPE(String value){
            this.value = value;
        }

        public String getValue(){
            return this.value;
        }

    }


    public static void main(String[] args) throws Exception {
        String source = "helloittx";
        System.out.println("原文: " + source);
        String key = "A1B2C3D4E5F60708";
        String encryptData = encryptDes(source, key);
        System.out.println("加密后: " + encryptData);
        String decryptData = decryptDes(encryptData, key);
        System.out.println("解密后: " + decryptData);



        generateKeyPair(); //生成文件形式公钥和私钥
        //generateKeyPairString();//生成字符串形式公钥和私钥

        source = "非对称加密RSA";// 要加密的字符串

        String cryptograph = encrypt(source);// 生成的密文
        String hexCrypt = bytes2Hex(cryptograph.getBytes());
        System.out.println("生成的密文--->" + hexCrypt);

//        String target = decrypt(HexUtil.hex2String(hexCrypt));// 解密密文
//        System.out.println("解密密文--->" + target);

        jdkRSA("123132");
    }

}
