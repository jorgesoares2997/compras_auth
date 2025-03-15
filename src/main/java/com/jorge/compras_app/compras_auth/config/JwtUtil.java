package com.jorge.compras_app.compras_auth.config;

import io.jsonwebtoken.Claims;
import io.jsonwebtoken.JwtParserBuilder;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.security.Keys;
import org.springframework.stereotype.Component;

import javax.crypto.SecretKey;
import java.nio.charset.StandardCharsets;
import java.util.Date;

@Component
public class JwtUtil {
    // Chave secreta codificada em Base64 (mínimo 256 bits para HS256)
    private final String SECRET_KEY = "qfXsYBVwgOFRtpTQvQL/1xJ5S77NwB9VJnO9zKVjTUZckctXl2o+8c5YMXPYAIopcm2823Np5r+nUljsCPvwzw==";
    private final long EXPIRATION_TIME = 1000 * 60 * 60 * 10; // 10 horas

    // Método para obter a chave secreta
    private SecretKey getSigningKey() {
        byte[] keyBytes = SECRET_KEY.getBytes(StandardCharsets.UTF_8);
        return Keys.hmacShaKeyFor(keyBytes); // Gera uma chave HMAC-SHA compatível
    }

    // Geração de token JWT
    public String generateToken(String email) {
        return Jwts.builder()
                .setSubject(email)
                .setIssuedAt(new Date())
                .setExpiration(new Date(System.currentTimeMillis() + EXPIRATION_TIME))
                .signWith(getSigningKey()) // Usa a chave secreta
                .compact();
    }

    // Extração do email do token
    public String extractEmail(String token) {
        Claims claims = getClaims(token);
        return claims.getSubject();
    }

    // Validação do token
    public boolean validateToken(String token) {
        try {
            getClaims(token); // Se conseguir extrair os claims, o token é válido
            return true;
        } catch (Exception e) {
            System.out.println("Erro ao validar token: " + e.getMessage());
            return false;
        }
    }

    // Método auxiliar para obter os Claims do token
    private Claims getClaims(String token) {
        JwtParserBuilder parserBuilder = Jwts.parser();
        parserBuilder.setSigningKey(getSigningKey());
        return parserBuilder.build()
                .parseClaimsJws(token)
                .getBody();
    }
}