package com.gannon.bouncycastle;

import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

import java.nio.file.Files;
import java.nio.file.Paths;

/**
 * @author gannon
 * @date 20221020
 */
public class RSATest {

    //pkcs8私钥
    private String pkcs8KeyString;

    // x509公钥
    private String x509KeyString;

    // pkcs1私钥
    private String pkcs1KeyString;

    // pkcs1公钥
    private String pkcs1PubKeyString;

//    @BeforeAll
//    public static void testGenerateKeyPair() throws Exception {
//        System.out.println("-------------生成秘钥文件-------------");
//        // 生成密钥对
//        var keyPair = RSA.generateKeyPair();
//        Pem.save(keyPair[0], Pem.KeyTypeEnum.PUBLIC_PKCS1_KEY);
//        Pem.save(keyPair[1], Pem.KeyTypeEnum.PRIVATE_PKCS1_KEY);
//        Pem.save(keyPair[1], Pem.KeyTypeEnum.PRIVATE_PKCS8_KEY);
//        Pem.save(keyPair[0], Pem.KeyTypeEnum.PUBLIC_X509_KEY);
//    }

    @BeforeEach
    public void keyInit() throws Exception {

        System.out.println("-------------获取秘钥文件-------------");
        System.out.println("====================PKCS8私钥====================");
        System.out.println();
        pkcs8KeyString = Files.readString(Paths.get("pkcs8.keystore"));
        System.out.println(pkcs8KeyString);
        System.out.println();
        System.out.println("====================x509公钥====================");
        System.out.println();
        x509KeyString = Files.readString(Paths.get("x509.keystore"));
        System.out.println(x509KeyString);
        System.out.println();
        System.out.println("====================PKCS1私钥====================");
        System.out.println();
        pkcs1KeyString = Files.readString(Paths.get("pkcs1.key"));
        System.out.println(pkcs1KeyString);
        System.out.println();
        System.out.println("====================PKCS1公钥====================");
        System.out.println();
        pkcs1PubKeyString = Files.readString(Paths.get("pkcs1.pem"));
        System.out.println(pkcs1PubKeyString);
        System.out.println();
    }

    @Test
    public void testJavaCryptor() throws Exception {

        String message = "hello world!!!";
        var encryptX509 = RSA.encrypt(message, Pem.toKey(x509KeyString), true);
        System.out.println("----------- encryptX509 -----------");
        System.out.println();
        System.out.println(encryptX509);
        System.out.println();

        var decryptPkcs8 = RSA.decrypt(encryptX509, Pem.toKey(pkcs8KeyString), true);
        System.out.println("----------- decryptPkcs8 -----------");
        System.out.println();
        System.out.println(decryptPkcs8);
        System.out.println();
        Assertions.assertEquals(message, decryptPkcs8);
    }

    @Test
    public void testOpenSSLCryptor() throws Exception {

        String message = "hello world!!!";
        var encryptPkcs1 = RSA.encrypt(message, pkcs1PubKeyString, false);
        System.out.println("----------- encryptPkcs1 -----------");
        System.out.println();
        System.out.println(encryptPkcs1);
        System.out.println();

        var decryptPkcs1 = RSA.decrypt(encryptPkcs1, pkcs1KeyString, false);
        System.out.println("----------- decryptPkcs1 -----------");
        System.out.println();
        System.out.println(decryptPkcs1);
        System.out.println();
        Assertions.assertEquals(message, decryptPkcs1);
    }

    @Test
    public void testJavaSignatureAndValidation() throws Exception {
        String message = "你好，世界！";
        var signaturePkcs8 = RSA.signature(message, Pem.toKey(pkcs8KeyString), true);
        System.out.println("----------- signaturePkcs8 -----------");
        System.out.println();
        System.out.println(signaturePkcs8);
        System.out.println();

        var validationPkcs8 = RSA.validation(signaturePkcs8, Pem.toKey(x509KeyString), true);
        System.out.println("----------- validationPkcs8 -----------");
        System.out.println();
        System.out.println(validationPkcs8);
        System.out.println();
        Assertions.assertEquals(message, validationPkcs8);
    }

    @Test
    public void testOpenSSLSignatureAndValidation() throws Exception {
        String message = "你好，世界！";
        var signaturePkcs1 = RSA.signature(message, pkcs1KeyString, false);
        System.out.println("----------- signaturePkcs1 -----------");
        System.out.println();
        System.out.println(signaturePkcs1);
        System.out.println();

        var validationPkcs1 = RSA.validation(signaturePkcs1, pkcs1PubKeyString, false);
        System.out.println("----------- validationPkcs1 -----------");
        System.out.println();
        System.out.println(validationPkcs1);
        System.out.println();
        Assertions.assertEquals(message, validationPkcs1);
    }
}
