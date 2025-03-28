package com.jorge.compras_app.compras_auth.config;

import io.jsonwebtoken.*;
import io.jsonwebtoken.security.Keys;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.stereotype.Component;

import javax.crypto.SecretKey;
import java.nio.charset.StandardCharsets;
import java.util.Base64;
import java.util.Date;

@Component
public class JwtUtil {
    private static final Logger logger = LoggerFactory.getLogger(JwtUtil.class);
    private final String SECRET_KEY = "qfXsYBVwgOFRtpTQvQL/1xJ5S77NwB9VJnO9zKVjTUZckctXl2o+8c5YMXPYAIopcm2823Np5r+nUljsCPvwzw==";
    private final long EXPIRATION_TIME = 1000 * 60 * 60 * 10; // 10 horas

    private SecretKey getSigningKey() {
        byte[] keyBytes = Base64.getDecoder().decode(SECRET_KEY); // Decodifica Base64
        return Keys.hmacShaKeyFor(keyBytes);
    }

    public String generateToken(String email) {
        Date now = new Date();
        Date expiryDate = new Date(now.getTime() + EXPIRATION_TIME);
        String token = Jwts.builder()
                .setSubject(email)
                .setIssuedAt(now)
                .setExpiration(expiryDate)
                .signWith(getSigningKey())
                .compact();
        logger.info("Token gerado para {}: expira em {}", email, expiryDate);
        return token;
    }

    public String extractEmail(String token) {
        Claims claims = getClaims(token);
        return claims.getSubject();
    }

    public boolean validateToken(String token) {
        try {
            Claims claims = getClaims(token);
            Date expiration = claims.getExpiration();
            if (expiration.before(new Date())) {
                logger.warn("Token expirado: {}", token);
                return false;
            }
            logger.debug("Token válido: {}", token);
            return true;
        } catch (ExpiredJwtException e) {
            logger.warn("Token expirado: {}", e.getMessage());
            return false;
        } catch (SignatureException e) {
            logger.error("Assinatura inválida: {}", e.getMessage());
            return false;
        } catch (Exception e) {
            logger.error("Erro ao validar token: {}", e.getMessage());
            return false;
        }
    }

    private Claims getClaims(String token) {
        JwtParserBuilder parserBuilder = Jwts.parser(); // Usa parserBuilder
        parserBuilder.setSigningKey(getSigningKey());
        return parserBuilder.build()
                .parseClaimsJws(token)
                .getBody();
    }
}