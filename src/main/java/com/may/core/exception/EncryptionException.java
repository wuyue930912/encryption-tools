package com.may.core.exception;

/**
 * 加密工具統一異常，用於封裝所有加密/解密/雜湊操作中的錯誤
 */
public class EncryptionException extends RuntimeException {

    public EncryptionException(String message) {
        super(message);
    }

    public EncryptionException(String message, Throwable cause) {
        super(message, cause);
    }
}
