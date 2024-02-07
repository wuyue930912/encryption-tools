package com.may.core;

import lombok.Data;
import org.springframework.boot.context.properties.ConfigurationProperties;

/**
 * 配置项
 */
@ConfigurationProperties(prefix = "encryption.tool")
@Data
public class EncryptionToolProperties {

    // BCrypt盐值
    private String BCryptSalt;

    // ASE密钥
    private String AESSecretKey;

    // RSA公钥
    private String RSAPublicKey;

    // RSA私钥
    private String RSAPrivateKey;

}
