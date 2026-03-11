package com.may.core.domain;

import lombok.Builder;
import lombok.Data;

import java.security.PrivateKey;
import java.security.PublicKey;

/**
 * SM2 密鑰對
 */
@Data
@Builder
public class SM2SecretKey {

    /**
     * 公鑰對象
     */
    private PublicKey publicKey;

    /**
     * Base64 編碼的公鑰字串
     */
    private String publicKeyStr;

    /**
     * 私鑰對象
     */
    private PrivateKey privateKey;

    /**
     * Base64 編碼的私鑰字串
     */
    private String privateKeyStr;

}