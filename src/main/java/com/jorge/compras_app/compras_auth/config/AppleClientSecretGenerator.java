package com.jorge.compras_app.compras_auth.config;

import io.jsonwebtoken.Jwts;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Component;

import java.security.KeyFactory;
import java.security.PrivateKey;
import java.security.spec.PKCS8EncodedKeySpec;
import java.util.Base64;

@Component
public class AppleClientSecretGenerator {

    @Value("${spring.security.oauth2.client.registration.apple.team-id}")
    private String teamId;

    @Value("${spring.security.oauth2.client.registration.apple.client-id}")
    private String clientId;

    @Value("${spring.security.oauth2.client.registration.apple.key-id}")
    private String keyId;

    @Value("${spring.security.oauth2.client.registration.apple.private-key}")
    private String privateKey;

    public String generate() throws Exception {
        byte[] keyBytes = Base64.getDecoder().decode(privateKey.replace("-----BEGIN PRIVATE KEY-----", "")
                .replace("-----END PRIVATE KEY-----", "").replaceAll("\\s", ""));
        PKCS8EncodedKeySpec spec = new PKCS8EncodedKeySpec(keyBytes);
        KeyFactory kf = KeyFactory.getInstance("EC");
        PrivateKey signingKey = kf.generatePrivate(spec);

        return Jwts.builder()
                .setIssuer(teamId)
                .setIssuedAt(new java.util.Date())
                .setExpiration(new java.util.Date(System.currentTimeMillis() + 1000 * 60 * 60 * 24 * 180)) // 6 meses
                .setAudience("https://appleid.apple.com")
                .setSubject(clientId)
                .signWith(signingKey)
                .compact();
    }
}