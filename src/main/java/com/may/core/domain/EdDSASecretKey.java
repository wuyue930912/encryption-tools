package com.may.core.domain;

import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;
import lombok.NoArgsConstructor;

import java.security.PrivateKey;
import java.security.PublicKey;

/**
 * EdDSA (Ed25519) 密鑰對
 */
@Data
@Builder
@NoArgsConstructor
@AllArgsConstructor
public class EdDSASecretKey {

    private PublicKey publicKey;

    private String publicKeyStr;

    private PrivateKey privateKey;

    private String privateKeyStr;
}