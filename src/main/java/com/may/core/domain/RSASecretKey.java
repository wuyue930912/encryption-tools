package com.may.core.domain;

import lombok.Builder;
import lombok.Data;

import java.security.PrivateKey;
import java.security.PublicKey;

@Data
@Builder
public class RSASecretKey {

    // 公钥
    private PublicKey publicKey;

    // 私钥
    private PrivateKey privateKey;

}
