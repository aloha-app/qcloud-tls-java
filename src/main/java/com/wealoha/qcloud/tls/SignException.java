package com.wealoha.qcloud.tls;

/**
 * sign/check fail
 * 
 * @author javamonk
 * @createTime 2016年2月25日 下午11:25:33
 */
public class SignException extends Exception {

    private static final long serialVersionUID = -8397197883237652065L;

    public SignException() {
    }

    public SignException(String message) {
        super(message);
    }

    public SignException(Exception e) {
        super(e);
    }

}
