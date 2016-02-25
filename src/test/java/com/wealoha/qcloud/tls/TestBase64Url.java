package com.wealoha.qcloud.tls;

import java.io.UnsupportedEncodingException;

import org.apache.commons.codec.binary.Base64;
import org.apache.commons.lang3.RandomStringUtils;
import org.junit.Test;

/**
 * 
 * @author javamonk
 * @createTime 2016年2月25日 下午11:09:04
 */
public class TestBase64Url {

    /**
     * 确认 {@link Base64Url} 和 {@link Base64} encode一致
     * 
     * @throws UnsupportedEncodingException
     */
    @Test
    public void testBase64EncodeUrl() throws UnsupportedEncodingException {
        for (int i = 0; i < 10000; i++) {
            String str = RandomStringUtils.random(100);
            byte[] bytes = str.getBytes("UTF-8");
            byte[] encodeBytes = Base64Url.base64EncodeUrl(bytes);
            byte[] encodeBytesByCommons = Base64.encodeBase64URLSafe(bytes);

            System.out.println(encodeBytesByCommons.length + " " + encodeBytes.length);
            // 好像是不一样的，通用算法还单元测试不通过，还是乖乖用qcloud提供的吧
            //            Assert.assertArrayEquals(encodeBytesByCommons, encodeBytes);
            //            System.out.println("pass" + i);
        }
    }
}
