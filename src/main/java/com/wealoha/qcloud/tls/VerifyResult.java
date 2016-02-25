package com.wealoha.qcloud.tls;

/**
 * 
 * @author javamonk
 * @createTime 2016年2月25日 下午11:24:57
 */
public class VerifyResult {

    private final int expireSeconds;

    private final int signTimestamp;

    public VerifyResult(int expireSeconds, int signTimestamp) {
        super();
        this.expireSeconds = expireSeconds;
        this.signTimestamp = signTimestamp;
    }

    public int getExpireSeconds() {
        return expireSeconds;
    }

    public int getSignTimestamp() {
        return signTimestamp;
    }

}
