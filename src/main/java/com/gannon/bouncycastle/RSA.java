package com.gannon.bouncycastle;

import org.bouncycastle.asn1.pkcs.PrivateKeyInfo;
import org.bouncycastle.asn1.x509.SubjectPublicKeyInfo;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.openssl.PEMKeyPair;
import org.bouncycastle.openssl.PEMParser;
import org.bouncycastle.openssl.jcajce.JcaPEMKeyConverter;

import javax.crypto.Cipher;
import java.io.File;
import java.io.FileWriter;
import java.io.IOException;
import java.io.StringReader;
import java.nio.charset.StandardCharsets;
import java.security.*;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;
import java.util.Base64;

public final class RSA {

    /**
     * 生成秘钥串对;公钥[0]，私钥[1]
     *
     * @throws NoSuchAlgorithmException
     */
    public static String[] generateKeyPair() throws NoSuchAlgorithmException {
        KeyPairGenerator keyPairGenerator = KeyPairGenerator.getInstance("RSA");
        keyPairGenerator.initialize(2048);
        KeyPair keyPair = keyPairGenerator.generateKeyPair();
        PublicKey publicKey = keyPair.getPublic();
        PrivateKey privateKey = keyPair.getPrivate();
        String[] keyStringPair = new String[2];
        keyStringPair[0] = Base64.getEncoder().encodeToString(publicKey.getEncoded());
        keyStringPair[1] = Base64.getEncoder().encodeToString(privateKey.getEncoded());
        return keyStringPair;
    }

    /**
     * 保存秘钥到文件
     *
     * @param targetDir     生成目标文件夹
     * @param keyStringPair 秘钥数组
     */
    public static void save(String targetDir, String[] keyStringPair) throws IOException {
        String publicKeyPath = targetDir + File.separator + "pub";
        String privateKeyPath = targetDir + File.separator + "priv";
        File pubFile = new File(publicKeyPath);
        File privFile = new File(privateKeyPath);
        try {
            if (!pubFile.exists()) {
                // 如果路径不存在,则创建
                if (!pubFile.getParentFile().exists()) {
                    pubFile.getParentFile().mkdirs();
                }
                pubFile.createNewFile();
            }
            if (!privFile.exists()) {
                // 如果路径不存在,则创建
                if (!privFile.getParentFile().exists()) {
                    privFile.getParentFile().mkdirs();
                }
                privFile.createNewFile();
            }
            try (FileWriter pubFileWriter = new FileWriter(pubFile);
                 FileWriter privFileWriter = new FileWriter(privFile);
            ) {
                pubFileWriter.write(keyStringPair[0]);
                pubFileWriter.flush();
                privFileWriter.write(keyStringPair[1]);
                privFileWriter.flush();
            } catch (IOException ignore) {
                throw ignore;
            }
        } catch (IOException ignore) {
            throw ignore;
        }
    }

    /**
     * 初始化公钥
     *
     * @param publicKeyString 公钥串
     * @param isX509          是否为X509格式 true:X509 false:pkcs1
     * @return 公钥
     * @throws Exception
     */
    private static PublicKey initPublicKey(String publicKeyString, boolean isX509) throws Exception {
        PublicKey publicKey = null;
        if (isX509) {
            byte[] publicKeyBytes = Base64.getDecoder().decode(publicKeyString);
            X509EncodedKeySpec x509EncodedKeySpec = new X509EncodedKeySpec(publicKeyBytes);
            KeyFactory keyFactory = KeyFactory.getInstance("RSA");
            publicKey = keyFactory.generatePublic(x509EncodedKeySpec);
        } else {
            StringReader reader = new StringReader(publicKeyString);
            PEMParser pemParser = new PEMParser(reader);
            Object o = pemParser.readObject();
            if (o instanceof SubjectPublicKeyInfo) {
                SubjectPublicKeyInfo publicKeyInfo = (SubjectPublicKeyInfo) o;
                JcaPEMKeyConverter converter = new JcaPEMKeyConverter().setProvider("BC");
                publicKey = converter.getPublicKey(publicKeyInfo);
            }
        }
        return publicKey;
    }

    /**
     * 初始化私钥
     *
     * @param privateKeyString 私钥串
     * @param isPkcs8          是否为pkcs8格式 true:pkcs8 false:pkcs1
     * @return 私钥
     * @throws Exception
     */
    private static PrivateKey initPrivateKey(String privateKeyString, boolean isPkcs8) throws Exception {
        PrivateKey privateKey = null;
        if (isPkcs8) {
            byte[] privateKeyBytes = Base64.getDecoder().decode(privateKeyString);
            PKCS8EncodedKeySpec pkcs8EncodedKeySpec = new PKCS8EncodedKeySpec(privateKeyBytes);
            KeyFactory keyFactory = KeyFactory.getInstance("RSA");
            privateKey = keyFactory.generatePrivate(pkcs8EncodedKeySpec);
        } else {
            // pkcs1
            StringReader reader = new StringReader(privateKeyString);
            PEMParser pemParser = new PEMParser(reader);
            Object o = pemParser.readObject();
            if (o instanceof PEMKeyPair) {
                PEMKeyPair pemKeyPair = (PEMKeyPair) o;
                JcaPEMKeyConverter converter = new JcaPEMKeyConverter().setProvider("BC");
                PrivateKeyInfo privateKeyInfo = pemKeyPair.getPrivateKeyInfo();
                privateKey = converter.getPrivateKey(privateKeyInfo);
            }
        }
        return privateKey;
    }

    /**
     * 使用公钥串加密
     *
     * @param message         需要加密的明文
     * @param publicKeyString 用于加密的公钥串
     * @param isX509          是否为X509格式 true:X509 false:pkcs1
     * @return
     * @throws Exception
     */
    public static String encrypt(String message, String publicKeyString, boolean isX509) throws Exception {
        byte[] bytes = message.getBytes(StandardCharsets.UTF_8);
        Cipher cipher;
        if (isX509) {
            cipher = Cipher.getInstance("RSA/ECB/PKCS1Padding");
            cipher.init(Cipher.ENCRYPT_MODE, initPublicKey(publicKeyString, true));
        } else {
            Security.addProvider(new BouncyCastleProvider());
            cipher = Cipher.getInstance("RSA/ECB/PKCS1Padding", "BC");
            cipher.init(Cipher.ENCRYPT_MODE, initPublicKey(publicKeyString, false));
        }
        return Base64.getEncoder().encodeToString(cipher.doFinal(bytes));
    }

    /**
     * 使用私钥串解密
     *
     * @param cipherMessage    需要解密的加密串
     * @param privateKeyString 用于解密的私钥串
     * @param isPkcs8          是否为pkcs8格式 true:pkcs8 false:pkcs1
     * @return
     * @throws Exception
     */
    public static String decrypt(String cipherMessage, String privateKeyString, boolean isPkcs8) throws Exception {
        byte[] decode = Base64.getDecoder().decode(cipherMessage);
        Cipher cipher;
        if (isPkcs8) {
            cipher = Cipher.getInstance("RSA/ECB/PKCS1Padding");
            cipher.init(Cipher.DECRYPT_MODE, initPrivateKey(privateKeyString, true));
        } else {
            Security.addProvider(new BouncyCastleProvider());
            cipher = Cipher.getInstance("RSA/ECB/PKCS1Padding", "BC");
            cipher.init(Cipher.DECRYPT_MODE, initPrivateKey(privateKeyString, false));
        }
        return new String(cipher.doFinal(decode), StandardCharsets.UTF_8);
    }

    /**
     * 使用私钥对明文进行签名/编码
     *
     * @param message          需要签名的明文
     * @param privateKeyString 用于签名的私钥
     * @param isPkcs8          是否为pkcs8格式 true:pkcs8 false:pkcs1
     * @return
     * @throws Exception
     */
    public static String signature(String message, String privateKeyString, boolean isPkcs8) throws Exception {
        byte[] bytes = message.getBytes(StandardCharsets.UTF_8);
        Cipher cipher;
        if (isPkcs8) {
            cipher = Cipher.getInstance("RSA/ECB/PKCS1Padding");
            cipher.init(Cipher.ENCRYPT_MODE, initPrivateKey(privateKeyString, true));
        } else {
            Security.addProvider(new BouncyCastleProvider());
            cipher = Cipher.getInstance("RSA/ECB/PKCS1Padding", "BC");
            cipher.init(Cipher.ENCRYPT_MODE, initPrivateKey(privateKeyString, false));
        }
        return Base64.getEncoder().encodeToString(cipher.doFinal(bytes));
    }

    /**
     * 使用公钥对签名消息进行验签/解码
     *
     * @param cipherMessage   签名消息
     * @param publicKeyString 用于验签的公钥
     * @param isX509          是否为X509格式 true:X509 false:pkcs1
     * @return
     * @throws Exception
     */
    public static String validation(String cipherMessage, String publicKeyString, boolean isX509) throws Exception {
        byte[] decode = Base64.getDecoder().decode(cipherMessage);
        Cipher cipher;
        if (isX509) {
            cipher = Cipher.getInstance("RSA/ECB/PKCS1Padding");
            cipher.init(Cipher.DECRYPT_MODE, initPublicKey(publicKeyString, true));
        } else {
            Security.addProvider(new BouncyCastleProvider());
            cipher = Cipher.getInstance("RSA/ECB/PKCS1Padding", "BC");
            cipher.init(Cipher.DECRYPT_MODE, initPublicKey(publicKeyString, false));
        }
        return new String(cipher.doFinal(decode), StandardCharsets.UTF_8);
    }
}
