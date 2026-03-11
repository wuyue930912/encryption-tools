package com.may.core.exception;

/**
 * 加密工具統一異常，用於封裝所有加密/解密/雜湊操作中的錯誤
 */
public class EncryptionException extends RuntimeException {

    private static final long serialVersionUID = 1L;

    public EncryptionException(String message) {
        super(message);
    }

    public EncryptionException(String message, Throwable cause) {
        super(message, cause);
    }

    /**
     * 創建無效密鑰異常
     */
    public static EncryptionException invalidKey(String algorithm) {
        return new EncryptionException(algorithm + "密鑰格式錯誤或無效");
    }

    /**
     * 創建加密失敗異常
     */
    public static EncryptionException encryptFailed(String algorithm, Throwable cause) {
        return new EncryptionException(algorithm + "加密失敗：" + cause.getMessage(), cause);
    }

    /**
     * 創建解密失敗異常
     */
    public static EncryptionException decryptFailed(String algorithm, Throwable cause) {
        return new EncryptionException(algorithm + "解密失敗：" + cause.getMessage(), cause);
    }

    /**
     * 創建哈希失敗異常
     */
    public static EncryptionException hashFailed(String algorithm, Throwable cause) {
        return new EncryptionException(algorithm + "哈希計算失敗：" + cause.getMessage(), cause);
    }

    /**
     * 創建簽名失效異常
     */
    public static EncryptionException signFailed(String algorithm, Throwable cause) {
        return new EncryptionException(algorithm + "簽名失敗：" + cause.getMessage(), cause);
    }

    /**
     * 創建驗籤失敗異常
     */
    public static EncryptionException verifyFailed(String algorithm, Throwable cause) {
        return new EncryptionException(algorithm + "驗籤失敗：" + cause.getMessage(), cause);
    }
}
