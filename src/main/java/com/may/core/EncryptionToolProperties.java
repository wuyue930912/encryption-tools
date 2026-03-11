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

    // SM2公鑰
    private String SM2PublicKey;

    // SM2私鑰
    private String SM2PrivateKey;

    // SM4密鑰
    private String SM4SecretKey;

    // ChaCha20-Poly1305密鑰
    private String ChaCha20SecretKey;

    // EdDSA公鑰
    private String EdDSAPublicKey;

    // EdDSA私鑰
    private String EdDSAPrivateKey;

    // 默認字符集編碼
    private String charset = "UTF-8";

    /**
     * Builder 靜態內部類，用於鏈式配置
     */
    public static class Builder {
        private final EncryptionToolProperties properties = new EncryptionToolProperties();

        public Builder BCryptSalt(String salt) {
            properties.setBCryptSalt(salt);
            return this;
        }

        public Builder AESSecretKey(String key) {
            properties.setAESSecretKey(key);
            return this;
        }

        public Builder RSAPublicKey(String key) {
            properties.setRSAPublicKey(key);
            return this;
        }

        public Builder RSAPrivateKey(String key) {
            properties.setRSAPrivateKey(key);
            return this;
        }

        public Builder ECCPublicKey(String key) {
            properties.setECCPublicKey(key);
            return this;
        }

        public Builder ECCPrivateKey(String key) {
            properties.setECCPrivateKey(key);
            return this;
        }

        public Builder SM2PublicKey(String key) {
            properties.setSM2PublicKey(key);
            return this;
        }

        public Builder SM2PrivateKey(String key) {
            properties.setSM2PrivateKey(key);
            return this;
        }

        public Builder SM4SecretKey(String key) {
            properties.setSM4SecretKey(key);
            return this;
        }

        public Builder ChaCha20SecretKey(String key) {
            properties.setChaCha20SecretKey(key);
            return this;
        }

        public Builder EdDSAPublicKey(String key) {
            properties.setEdDSAPublicKey(key);
            return this;
        }

        public Builder EdDSAPrivateKey(String key) {
            properties.setEdDSAPrivateKey(key);
            return this;
        }

        public Builder charset(String charset) {
            properties.setCharset(charset);
            return this;
        }

        public EncryptionToolProperties build() {
            return properties;
        }
    }

    public static Builder builder() {
        return new Builder();
    }

}