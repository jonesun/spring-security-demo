package com.jonesun.multiplehttpsecurityserver;

import com.nimbusds.jose.JOSEException;
import com.nimbusds.jose.JWSAlgorithm;
import com.nimbusds.jose.JWSHeader;
import com.nimbusds.jose.JWSSigner;
import com.nimbusds.jose.crypto.RSASSASigner;
import com.nimbusds.jose.crypto.RSASSAVerifier;
import com.nimbusds.jwt.JWTClaimsSet;
import com.nimbusds.jwt.SignedJWT;
import org.apache.commons.lang3.RandomStringUtils;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.GrantedAuthority;

import java.security.KeyFactory;
import java.security.NoSuchAlgorithmException;
import java.security.interfaces.RSAPrivateKey;
import java.security.interfaces.RSAPublicKey;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;
import java.text.ParseException;
import java.util.Base64;
import java.util.Collection;
import java.util.Date;
import java.util.stream.Collectors;

/**
 * @author jone.sun
 * @date 2020-12-25 17:20
 */
public class JWTUtils {

    /**
     * 过期时间50秒
     */
    private static final long EXPIRE_TIME = 1000 * 50;

    //todo 这里仅仅为了演示rsa的加解密功能，实际项目中需自行生成好再读取。或者使用jks的方式读取
    //公钥
    private static String publicKeyStr = "MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAvSja2vpalTbaNg8ChQt133AC6RPD3mpvkPzezb5lw48+AmVyodtJ817Uoi6p+QpkeNyxoivRYEq4Swyf8F18galvstKsR56cjr4oG4XngV0IKNbG+u+/LWqrI8i64PVhn5+wV8L9gwxF/F6tqh4uxoMLK1UAiQ+Pbwk7VTCiVgDAllIk8hAxGKXYN2e2i/ZjeP3jjvyClTYxBKEXWD+EqTflGnbLDs9yqcLgjwcpH+9csY6b7KCIbvFUY/CWJi9n7shRYZZHv3aTJAMbo3VpwDEOpXQXbrZw6mYF7OrHjWVWiMmUHhaVXk73gOx/DbyNp89UOa+t7wyk0A5coPii5wIDAQAB";

    //私钥
    private static String privateKeyStr = "MIIEvQIBADANBgkqhkiG9w0BAQEFAASCBKcwggSjAgEAAoIBAQC9KNra+lqVNto2DwKFC3XfcALpE8Peam+Q/N7NvmXDjz4CZXKh20nzXtSiLqn5CmR43LGiK9FgSrhLDJ/wXXyBqW+y0qxHnpyOvigbheeBXQgo1sb6778taqsjyLrg9WGfn7BXwv2DDEX8Xq2qHi7GgwsrVQCJD49vCTtVMKJWAMCWUiTyEDEYpdg3Z7aL9mN4/eOO/IKVNjEEoRdYP4SpN+UadssOz3KpwuCPBykf71yxjpvsoIhu8VRj8JYmL2fuyFFhlke/dpMkAxujdWnAMQ6ldBdutnDqZgXs6seNZVaIyZQeFpVeTveA7H8NvI2nz1Q5r63vDKTQDlyg+KLnAgMBAAECggEAYSK3sDdbiMBQMe5nRtbpwsGMXRAvRum1POj9qP2a2F+YYjaiNQec5ALQgjAgTKjPi1kZRsPlkuML3E4xW4dGRncxysxwd561mn9/rRKIHWAerooMSBQRQktCcu/DN34KkaO5NHgHIuKMldowp+kz7/CfLbNKwRdieoxtEYQV+L8rjCYOQUHJMez02G8N4IRkLmY73XlHKQmKBHSuLP/IKNZQbJrmr6Tsjj5NoBKHTSuuEY3QDDqMbZHNh3XYoYOVNnFbqDRjlUx4BLQgLpz5KBOxcV+xP5xyuPZuUlWuS9+3ADeiCptiTO9fDZHxZDHjw0qJo7KBWgLbL+e14KCO8QKBgQDsot+ZVJI9jpOoqPbej7jDDlRSo3zV73IfIHKPiNnbCRJgFUCYXIf6xtOi5+z908T1Cv3e6aQGW8pNUTwco1EMuNgMIPmITMoq6NWzBsbIVw+plIWpOzJQnIPsN8UZAAaxtP+DLrYCgOKDfQa7jKgMlgjWIzIovP7e2oG2eWKTewKBgQDMo207lNmvqIMr8LD3guEjN7GJOVp8yHKbpqMjZwwLoI3BADJDWef0nT/fyB1agfvq80IeA3f6H/ID0qztkNVEqfQWoDrN08Q8pn5K+GGXIirkSivzIM4+mV1SOHDgyoNks8pK2gGmG5bO3SvUlo1Q6MW1pXOrSVwJ0krltvTMhQKBgFIEhdGEQYe6ci1kGuS7FcPtpIZcCfmwm3J0caCUQ0Yq18abtx7X+32NCm+NSVQU4VA5dhKcEnDtwamYvWgDpyTssF1L1JFMZEoJF4CMmbt4iYIyaz1juiW8ifEGx3bJzogrfuA+AXHOsDP40quQrfJm0js+SbVbBE/Dlm/jlKofAoGAUuVQ9nXRyOqGWGJkDZ+i+9UvwdrN4QaCBrN2Gn0/z+X2BlzB/66H2/tnSIuT+Hn3RrHL8sSM8XHHY+0PyByHiA0gp5m4uHA0ai03s77yKXrZzSiOrSp44brWptvePfFLUJvUMoYlbNh4Osw1WSSzkjb5ACBJvvU0p3XciTmX6NECgYEAgoN0GvFls1A+Jhcr9BqVCk+jHcAUhxmQtuQjgGPnUUovrbCc/PtfiM9FKvpxa30SbBjW4t7itfqKLg1zpJcnCOhrhQl7QnnRpGFkRh9STA3xsjsp/dRS5popNR6iGOvEulgobWxK9Ogln61mreZFQSmHVjWPSQQOitJiKWmWxAI=";
//
//    static {
//        try {
//            generateRSAKey();
//        } catch (NoSuchAlgorithmException e) {
//            e.printStackTrace();
//        }
//    }
//
//    private static void generateRSAKey() throws NoSuchAlgorithmException {
//
//        KeyPairGenerator keyPairGenerator = KeyPairGenerator.getInstance("RSA");
//        keyPairGenerator.initialize(2048);
//        KeyPair keyPair = keyPairGenerator.generateKeyPair();
//        RSAPublicKey publicKey = (RSAPublicKey) keyPair.getPublic();
//        RSAPrivateKey privateKey = (RSAPrivateKey) keyPair.getPrivate();
//
//        publicKeyStr = Base64.getEncoder().encodeToString(publicKey.getEncoded());
//        privateKeyStr = Base64.getEncoder().encodeToString(privateKey.getEncoded());
//        System.out.println("公钥：" + publicKeyStr);
//        System.out.println("私钥：" + privateKeyStr);
//    }


    public static String buildToken(Authentication authentication) {
        try {


            //keyId 全数字的随机值
            String keyId = RandomStringUtils.random(32, false, true);

            JWSSigner jwsSigner = new RSASSASigner(getRSAPrivateKey(privateKeyStr));

            JWSHeader header = new JWSHeader.Builder(JWSAlgorithm.RS512).keyID(keyId).build();

            final String payloadText = "I am jonesun [RSA]";
            JWTClaimsSet claimsSet = new JWTClaimsSet.Builder()
                    .subject(authentication.getName())
                    .issuer("http://localhost:8080/web-server-jwt/")
                    // 设置登录用户的角色
                    .audience(authentication.getAuthorities().stream().map(GrantedAuthority::getAuthority).collect(Collectors.toList()))
                    .claim("payloadText", payloadText)
                    .expirationTime(new Date(System.currentTimeMillis() + EXPIRE_TIME))
                    .build();

            SignedJWT signedJWT = new SignedJWT(header, claimsSet);
            signedJWT.sign(jwsSigner);
            return signedJWT.serialize();
        } catch (Exception e) {
            e.printStackTrace();
        }
        return null;
    }

    public static JWTClaimsSet verifyToken(String token) {
        SignedJWT jwt = null;
        try {
            jwt = SignedJWT.parse(token);
            //添加私密钥匙 进行解密
            RSASSAVerifier rsassaVerifier = new RSASSAVerifier(getRSAPublicKey(publicKeyStr));
            //校验是否有效
            if (!jwt.verify(rsassaVerifier)) {
                //todo token无效
                return null;
            }
            return jwt.getJWTClaimsSet();
        } catch (ParseException | JOSEException | NoSuchAlgorithmException | InvalidKeySpecException e) {
            e.printStackTrace();
            return null;
        }
    }

    private static RSAPublicKey getRSAPublicKey(String publicKeyStr) throws NoSuchAlgorithmException, InvalidKeySpecException {
        // base64编码的公钥
        byte[] decoded = Base64.getDecoder().decode(publicKeyStr);
        return (RSAPublicKey) KeyFactory.getInstance("RSA").generatePublic(new X509EncodedKeySpec(decoded));
    }

    private static RSAPrivateKey getRSAPrivateKey(String privateKeyStr) throws NoSuchAlgorithmException, InvalidKeySpecException {
        byte[] decoded = Base64.getDecoder().decode(privateKeyStr);
        return (RSAPrivateKey) KeyFactory.getInstance("RSA").generatePrivate(new PKCS8EncodedKeySpec(decoded));
    }

}
