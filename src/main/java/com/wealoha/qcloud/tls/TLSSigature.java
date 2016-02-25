package com.wealoha.qcloud.tls;

import java.io.CharArrayReader;
import java.io.Reader;
import java.nio.charset.Charset;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.Security;
import java.security.Signature;
import java.util.Arrays;
import java.util.HashMap;
import java.util.Map;
import java.util.concurrent.TimeUnit;
import java.util.zip.Deflater;
import java.util.zip.Inflater;

import org.apache.commons.codec.binary.Base64;
import org.bouncycastle.asn1.pkcs.PrivateKeyInfo;
import org.bouncycastle.asn1.x509.SubjectPublicKeyInfo;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.openssl.PEMParser;
import org.bouncycastle.openssl.jcajce.JcaPEMKeyConverter;

import com.fasterxml.jackson.core.type.TypeReference;
import com.fasterxml.jackson.databind.DeserializationFeature;
import com.fasterxml.jackson.databind.ObjectMapper;

/**
 * 
 * @author javamonk
 * @author 原作者可能是腾讯xiaojun
 * @createTime 2016年2月25日 下午10:41:22
 */
public class TLSSigature {

    private static ObjectMapper mapper = null;

    static {
        mapper = new com.fasterxml.jackson.databind.ObjectMapper();
        mapper.disable(DeserializationFeature.FAIL_ON_UNKNOWN_PROPERTIES);

        Security.addProvider(new BouncyCastleProvider());
    }

    /**
     * 生成 tls 票据，有效期默认为 180 天
     * 
     * @param skdAppid 应用的 sdkappid
     * @param identifier 用户 id
     * @param privStr 私钥文件内容
     * @return
     * @throws SignException
     */
    public static SignResult sign(long skdAppid, String identifier, String privStr)
            throws SignException {
        return sign(skdAppid, identifier, privStr, (int) TimeUnit.DAYS.toSeconds(180));
    }

    /**
     * 生成 tls 票据
     * 
     * @param skdAppid 应用的 sdkappid
     * @param identifier 用户 id
     * @param privStr 私钥文件内容
     * @param expireSeconds 有效期，以秒为单位，推荐时长一个月
     * @return
     * @throws SignException
     */
    public static SignResult sign(long skdAppid, String identifier, String privStr,
            int expireSeconds) throws SignException {
        try {
            Reader reader = new CharArrayReader(privStr.toCharArray());
            JcaPEMKeyConverter converter = new JcaPEMKeyConverter();
            PEMParser parser = new PEMParser(reader);
            Object obj = parser.readObject();
            parser.close();
            PrivateKey privKeyStruct = converter.getPrivateKey((PrivateKeyInfo) obj);

            String jsonString = "{" + "\"TLS.account_type\":\"" + 0 + "\","
                    + "\"TLS.identifier\":\"" + identifier + "\"," + "\"TLS.appid_at_3rd\":\"" + 0
                    + "\"," + "\"TLS.sdk_appid\":\"" + skdAppid + "\"," + "\"TLS.expire_after\":\""
                    + expireSeconds + "\"," + "\"TLS.version\": \"201512300000\"" + "}";

            int signTime = (int) (System.currentTimeMillis() / 1000);
            String time = String.valueOf(signTime);
            String serialString = "TLS.appid_at_3rd:" + 0 + "\n" + "TLS.account_type:" + 0 + "\n"
                    + "TLS.identifier:" + identifier + "\n" + "TLS.sdk_appid:" + skdAppid + "\n"
                    + "TLS.time:" + time + "\n" + "TLS.expire_after:" + expireSeconds + "\n";

            //Create Signature by SerialString
            Signature signature = Signature.getInstance("SHA256withECDSA", "BC");
            signature.initSign(privKeyStruct);
            signature.update(serialString.getBytes(Charset.forName("UTF-8")));
            byte[] signatureBytes = signature.sign();

            String sigTLS = Base64.encodeBase64String(signatureBytes);

            //Add TlsSig to jsonString
            Map<String, Object> map = new HashMap<String, Object>();
            map.put("TLS.sig", sigTLS);
            map.put("TLS.time", time);
            // TODO FUCK 一个手拼json，一个json jsonString = mapper.writeValueAsString(map);

            //compression
            Deflater compresser = new Deflater();
            compresser.setInput(jsonString.getBytes(Charset.forName("UTF-8")));

            compresser.finish();
            byte[] compressBytes = new byte[512];
            int compressBytesLength = compresser.deflate(compressBytes);
            compresser.end();
            String userSig = new String(Base64Url.base64EncodeUrl(Arrays.copyOfRange(compressBytes,
                    0, compressBytesLength)));

            return new SignResult(userSig, expireSeconds, signTime);
        } catch (Exception e) {
            throw new SignException(e);
        }
    }

    public static VerifyResult verify(String urlSig, long sdkAppid, String identifier,
            String publicKey) throws SignException {

        try {
            //DeBaseUrl64 urlSig to json
            Base64 decoder = new Base64();

            byte[] compressBytes = Base64Url.base64DecodeUrl(urlSig.getBytes(Charset
                    .forName("UTF-8")));

            //Decompression
            Inflater decompression = new Inflater();
            decompression.setInput(compressBytes, 0, compressBytes.length);
            byte[] decompressBytes = new byte[1024];
            int decompressLength = decompression.inflate(decompressBytes);
            decompression.end();

            String jsonString = new String(Arrays.copyOfRange(decompressBytes, 0, decompressLength));

            //Get TLS.Sig from json
            Map<String, Object> map = mapper.readValue(jsonString,
                    new TypeReference<Map<String, Object>>() {});
            String sigTLS = (String) map.get("TLS.sig");
            System.out.println(map.keySet());

            //debase64 TLS.Sig to get serailString
            byte[] signatureBytes = decoder.decode(sigTLS.getBytes(Charset.forName("UTF-8")));

            String strSdkAppid = (String) map.get("TLS.sdk_appid");
            String sigTime = (String) map.get("TLS.time");
            String sigExpire = (String) map.get("TLS.expire_after");

            if (Integer.parseInt(strSdkAppid) != sdkAppid) {
                throw new SignException("sdkappid " + strSdkAppid
                        + " in tls sig not equal sdkappid " + sdkAppid + " in request");
            }

            int signTimestamp = Integer.parseInt(sigTime);
            if (System.currentTimeMillis() / 1000 - signTimestamp > Long.parseLong(sigExpire)) {
                throw new SignExpiredException(signTimestamp);
            }

            //Get Serial String from json
            String SerialString = "TLS.appid_at_3rd:" + 0 + "\n" + "TLS.account_type:" + 0 + "\n"
                    + "TLS.identifier:" + identifier + "\n" + "TLS.sdk_appid:" + sdkAppid + "\n"
                    + "TLS.time:" + sigTime + "\n" + "TLS.expire_after:" + sigExpire + "\n";

            Reader reader = new CharArrayReader(publicKey.toCharArray());
            PEMParser parser = new PEMParser(reader);
            JcaPEMKeyConverter converter = new JcaPEMKeyConverter();
            Object obj = parser.readObject();
            parser.close();
            PublicKey pubKeyStruct = converter.getPublicKey((SubjectPublicKeyInfo) obj);

            Signature signature = Signature.getInstance("SHA256withECDSA", "BC");
            signature.initVerify(pubKeyStruct);
            signature.update(SerialString.getBytes(Charset.forName("UTF-8")));
            if (signature.verify(signatureBytes)) {
                return new VerifyResult(Integer.parseInt(sigExpire), signTimestamp);
            } else {
                throw new SignException();
            }
        } catch (Exception e) {
            throw new SignException(e);
        }
    }

}
