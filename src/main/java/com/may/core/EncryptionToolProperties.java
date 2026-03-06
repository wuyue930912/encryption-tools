package com.may.core;

import lombok.Data;
import org.springframework.boot.context.properties.ConfigurationProperties;

/**
 * 配置項
 */
@ConfigurationProperties(prefix = "encryption.tool")
@Data
public class EncryptionToolProperties {

    // BCrypt鹽值
    private String BCryptSalt;

    // AES密鑰
    private String AESSecretKey;

    // RSA公鑰
    private String RSAPublicKey;

    // RSA私鑰
    private String RSAPrivateKey;

    // ECC公鑰
    private String ECCPublicKey;

    // ECC私鑰
    private String ECCPrivateKey;

}
