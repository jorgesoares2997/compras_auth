package com.jorge.compras_app.compras_auth.config;

import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.security.Keys;
import io.jsonwebtoken.Claims;
import org.springframework.stereotype.Component;

import java.util.Date;
import java.nio.charset.StandardCharsets;
import javax.crypto.SecretKey;

@Component
public class JwtUtil {
    private final String SECRET_KEY = "qfXsYBVwgOFRtpTQvQL/1xJ5S77NwB9VJnO9zKVjTUZckctXl2o+8c5YMXPYAIop\n" + //
            "cm2823Np5r+nUljsCPvwzw==";
    private final long EXPIRATION_TIME = 1000 * 60 * 60 * 10; // 10 horas

    private SecretKey getSigningKey() {
        byte[] keyBytes = SECRET_KEY.getBytes(StandardCharsets.UTF_8);
        return Keys.hmacShaKeyFor(keyBytes);
    }

    public String generateToken(String email) {
        return Jwts.builder()
                .subject(email)
                .issuedAt(new Date())
                .expiration(new Date(System.currentTimeMillis() + EXPIRATION_TIME))
                .signWith(getSigningKey())
                .compact();
    }

    public String extractEmail(String token) {
        Claims claims = Jwts.parser()
                .setSigningKey(getSigningKey()) // Corrigido
                .build()
                .parseClaimsJws(token)
                .getBody();
        return claims.getSubject();
    }

    public boolean validateToken(String token) {
        try {
            Jwts.parser()
                    .setSigningKey(getSigningKey()) // Corrigido
                    .build()
                    .parseClaimsJws(token);
            return true;
        } catch (Exception e) {
            System.out.println("Erro ao validar token: " + e.getMessage());
            return false;
        }
    }
}