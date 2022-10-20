package com.gannon.bouncycastle;

import org.bouncycastle.asn1.ASN1Encodable;
import org.bouncycastle.asn1.ASN1Primitive;
import org.bouncycastle.asn1.pkcs.PrivateKeyInfo;
import org.bouncycastle.asn1.x509.SubjectPublicKeyInfo;
import org.bouncycastle.util.encoders.Base64;
import org.bouncycastle.util.io.pem.PemObject;
import org.bouncycastle.util.io.pem.PemWriter;

import java.io.IOException;
import java.io.StringWriter;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.nio.file.StandardOpenOption;

/**
 * @author gannon
 */
public class Pem {
    /**
     * 根据对应秘钥和秘钥类型格式化为pem秘钥格式
     *
     * @param key     秘钥(Base64编码后的)
     * @param keyType 秘钥类型
     * @return
     */
    public static String toPem(String key, KeyTypeEnum keyType) throws Exception {
        if (key == null || key.trim().length() <= 0) {
            throw new IllegalArgumentException("秘钥不能为空或空串");
        }
        byte[] keyBytes = Base64.decode(key);
        StringBuilder builder = new StringBuilder();
        ASN1Primitive primitive;
        switch (keyType) {
            case PRIVATE_PKCS8_KEY:
                builder.append("-----BEGIN PRIVATE KEY-----");
                builder.append("\n");
                each64(key, builder);
                builder.append("-----END PRIVATE KEY-----");
                break;
            case PRIVATE_PKCS1_KEY:
                PrivateKeyInfo pkInfo = PrivateKeyInfo.getInstance(keyBytes);
                ASN1Encodable encodable = pkInfo.parsePrivateKey();
                primitive = encodable.toASN1Primitive();
                builder.append(pkcs1ToPem(primitive.getEncoded(), false));
                break;
            case PUBLIC_PKCS1_KEY:
                SubjectPublicKeyInfo spkInfo = SubjectPublicKeyInfo.getInstance(keyBytes);
                primitive = spkInfo.parsePublicKey();
                builder.append(pkcs1ToPem(primitive.getEncoded(), true));
                break;
            default:
                builder.append("-----BEGIN PUBLIC KEY-----");
                builder.append("\n");
                each64(key, builder);
                builder.append("-----END PUBLIC KEY-----");
        }
        return builder.toString();
    }

    /**
     * 根据每64个字符换行
     *
     * @param key     秘钥
     * @param builder 临时串
     */
    private static void each64(String key, StringBuilder builder) {
        int count = (key.length() - 1) / 64 + 1;
        for (int i = 0; i < count; i++) {
            String substring = "";
            if (i + 1 == count) {
                substring = key.substring(i * 64);
            } else {
                substring = key.substring(i * 64, i * 64 + 64);
            }
            builder.append(substring);
            builder.append("\n");
        }
    }


    /**
     * 将PKCS1格式转换为Pem格式
     *
     * @param pcks1KeyBytes pkcs1密钥字节数据
     * @param isPublic      是否公钥，true: 公钥 false: 私钥
     * @return pem字符串
     * @throws Exception
     */
    private static String pkcs1ToPem(byte[] pcks1KeyBytes, boolean isPublic) throws Exception {
        PemObject pemObject;
        if (isPublic) {
            pemObject = new PemObject("RSA PUBLIC KEY", pcks1KeyBytes);
        } else {
            pemObject = new PemObject("RSA PRIVATE KEY", pcks1KeyBytes);
        }
        StringWriter stringWriter = new StringWriter();
        PemWriter pemWriter = new PemWriter(stringWriter);
        pemWriter.writeObject(pemObject);
        pemWriter.close();
        return stringWriter.toString();
    }

    /**
     * 将密钥串转换为pem格式并保存到当前目录
     *
     * @param key     密钥串
     * @param keyType 密钥类型
     * @throws Exception
     */
    public static void save(String key, KeyTypeEnum keyType) throws Exception {
        switch (keyType) {
            case PRIVATE_PKCS1_KEY:
                toPem(key, keyType, Paths.get("pkcs1.key"));
                break;
            case PRIVATE_PKCS8_KEY:
                toPem(key, keyType, Paths.get("pkcs8.keystore"));
                break;
            case PUBLIC_PKCS1_KEY:
                toPem(key, keyType, Paths.get("pkcs1.pem"));
            default:
                toPem(key, keyType, Paths.get("x509.keystore"));
        }
    }

    /**
     * 根据对应秘钥和秘钥类型生成特定后缀的秘钥文件
     *
     * @param key     秘钥
     * @param keyType 秘钥类型
     * @param dest    写出文件路径
     * @return
     */
    public static void toPem(String key, KeyTypeEnum keyType, Path dest) throws Exception {
        Files.writeString(dest, toPem(key, keyType), StandardOpenOption.WRITE, StandardOpenOption.CREATE);
    }

    /**
     * 根据秘钥文件和秘钥类型格式化为pem格式并保存到特定路径
     *
     * @param from    源秘钥文件
     * @param keyType 秘钥类型
     * @param dest    目标保存路径
     * @throws IOException
     */
    public static void transferToPem(Path from, KeyTypeEnum keyType, Path dest) throws Exception {
        toPem(Files.readString(from), keyType, dest);
    }

    /**
     * 解包Pem文件格式获取java原生对应x509或pkcs8秘钥
     *
     * @param pem pem文件格式内容
     * @return 秘钥串
     */
    public static String toKey(String pem) {
        pem = pem.substring(pem.indexOf("KEY-----") + "KEY-----".length());
        pem = pem.substring(0, pem.indexOf("-----END"));
        pem = pem.replace("\n", "");
        return pem;
    }

    /**
     * 根据pem格式文件路径和秘钥类型获取java原生对应x509或pkcs8秘钥
     *
     * @param pemPath pem文件路径
     * @return 秘钥串
     * @throws IOException
     */
    public static String toKey(Path pemPath) throws IOException {
        return toKey(Files.readString(pemPath));
    }

    public enum KeyTypeEnum {
        PUBLIC_X509_KEY,
        PUBLIC_PKCS1_KEY,
        PRIVATE_PKCS1_KEY,
        PRIVATE_PKCS8_KEY,
    }
}

