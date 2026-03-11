package com.may.core.exception;

/**
 * 密鑰無效異常
 */
public class InvalidKeyException extends EncryptionException {

    public InvalidKeyException(String message) {
        super(message);
    }

    public InvalidKeyException(String message, Throwable cause) {
        super(message, cause);
    }
}