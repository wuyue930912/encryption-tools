package com.may.core.domain;

import lombok.Builder;
import lombok.Data;

import java.security.PrivateKey;
import java.security.PublicKey;

@Data
@Builder
public class ECCSecretKey {

    // 公钥
    private PublicKey publicKey;

    private String publicKeyStr;

    // 私钥
    private PrivateKey privateKey;

    private String privateKeyStr;

}
