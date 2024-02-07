package com.may.core;

import lombok.Data;
import org.springframework.boot.context.properties.ConfigurationProperties;

/**
 * 使用者配置的属性
 */
@ConfigurationProperties(prefix = "encryption.tool")
@Data
public class EncryptionToolProperties {

    // BCrypt盐值
    private String BCryptSalt;

    // ASE密钥
    private byte[] AESSecretKey;

    // RSA公钥
    private byte[] RSAPublicKey;

    // RSA私钥
    private byte[] RSAPrivateKey;

}
