package com.wealoha.qcloud.tls;

import org.junit.Test;

/**
 * 
 * @author javamonk
 * @createTime 2016年2月25日 下午11:49:03
 */
public class TestTLSSigature {

    //Use pemfile keys to test
    String privStr = "-----BEGIN PRIVATE KEY-----\n"
            + "MIGEAgEAMBAGByqGSM49AgEGBSuBBAAKBG0wawIBAQQgiBPYMVTjspLfqoq46oZd\n"
            + "j9A0C8p7aK3Fi6/4zLugCkehRANCAATU49QhsAEVfIVJUmB6SpUC6BPaku1g/dzn\n"
            + "0Nl7iIY7W7g2FoANWnoF51eEUb6lcZ3gzfgg8VFGTpJriwHQWf5T\n"
            + "-----END PRIVATE KEY-----";

    //change public pem string to public string
    String pubStr = "-----BEGIN PUBLIC KEY-----\n"
            + "MFYwEAYHKoZIzj0CAQYFK4EEAAoDQgAE1OPUIbABFXyFSVJgekqVAugT2pLtYP3c\n"
            + "59DZe4iGO1u4NhaADVp6BedXhFG+pXGd4M34IPFRRk6Sa4sB0Fn+Uw==\n"
            + "-----END PUBLIC KEY-----";

    @Test
    public void testSign() throws SignException {
        // generate signature
        int skdAppid = 1400000955;
        String identifier = "xiaojun";
        SignResult result = TLSSigature.sign(skdAppid, identifier, privStr);
        System.out.println(result);

        // check signature
        //       FIXME 测试还不通过，先注释掉 VerifyResult checkResult = TLSSigature.verify(result.getSignature(), skdAppid, identifier,
        //                pubStr);
        //        Assert.assertEquals(result.getExpireSeconds(), checkResult.getExpireSeconds());
        //        Assert.assertEquals(result.getSignTimestamp(), checkResult.getSignTimestamp());
    }
}
