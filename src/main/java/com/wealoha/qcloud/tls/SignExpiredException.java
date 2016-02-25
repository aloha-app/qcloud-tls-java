package com.wealoha.qcloud.tls;

/**
 * TLS过期
 * 
 * @author javamonk
 * @createTime 2016年2月25日 下午11:30:40
 */
public class SignExpiredException extends SignException {

    private static final long serialVersionUID = -1739324771730892197L;

    private final int signTimestamp;

    public SignExpiredException(int signTimestamp) {
        super();
        this.signTimestamp = signTimestamp;
    }

    public int getSignTimestamp() {
        return signTimestamp;
    }
}
