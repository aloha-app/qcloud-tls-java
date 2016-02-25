package com.wealoha.qcloud.tls;

/**
 * 
 * @author javamonk
 * @createTime 2016年2月25日 下午11:21:23
 */
public class SignResult {

    private final String signature;

    private final int expireSeconds;

    private final int signTimestamp;

    public SignResult(String signature, int expireSeconds, int signTimestamp) {
        super();
        this.signature = signature;
        this.expireSeconds = expireSeconds;
        this.signTimestamp = signTimestamp;
    }

    public String getSignature() {
        return signature;
    }

    public int getExpireSeconds() {
        return expireSeconds;
    }

    /**
     * sign time
     * 
     * @return seconds from epoch
     */
    public int getSignTimestamp() {
        return signTimestamp;
    }

}
