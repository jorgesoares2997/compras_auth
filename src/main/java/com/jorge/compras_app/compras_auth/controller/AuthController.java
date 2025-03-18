package com.jorge.compras_app.compras_auth.controller;

import io.jsonwebtoken.Claims;
import io.jsonwebtoken.Jws;
import io.jsonwebtoken.JwtParserBuilder;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.SigningKeyResolver;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;
import org.springframework.web.client.RestTemplate;

import com.jorge.compras_app.compras_auth.config.JwtUtil;
import com.jorge.compras_app.compras_auth.model.User;
import com.jorge.compras_app.compras_auth.service.UserService;

import java.security.PublicKey;

@RestController
@RequestMapping("/api/auth")
@CrossOrigin(origins = "*")
public class AuthController {

    @Autowired
    private UserService userService;

    @Autowired
    private JwtUtil jwtUtil;

    private final RestTemplate restTemplate = new RestTemplate();

    // Endpoint de registro existente
    @PostMapping("/register")
    public ResponseEntity<String> register(@RequestBody User user) {
        System.out.println("Registrando usuário: " + user.getEmail());
        try {
            User savedUser = userService.saveUser(user);
            System.out.println("Usuário salvo com ID: " + savedUser.getId());
            return ResponseEntity.ok("Usuário registrado com sucesso");
        } catch (IllegalArgumentException e) {
            return ResponseEntity.status(400).body("Email já está em uso");
        }
    }

    // Endpoint de login existente
    @PostMapping("/login")
    public ResponseEntity<String> login(@RequestBody User user) {
        System.out.println("Tentativa de login com email: " + user.getEmail());
        if (userService.validateCredentials(user.getEmail(), user.getPassword())) {
            String token = jwtUtil.generateToken(user.getEmail());
            System.out.println("Login bem-sucedido, token gerado: " + token);
            return ResponseEntity.ok(token);
        }
        System.out.println("Credenciais inválidas para: " + user.getEmail());
        return ResponseEntity.status(401).body("Credenciais inválidas");
    }

    // Login com Google (já existente)
    @PostMapping("/google-login")
    public ResponseEntity<String> loginWithGoogle(@RequestBody GoogleLoginRequest request) {
        System.out.println("Tentativa de login com Google: " + request.getAccessToken());
        try {
            String tokenInfoUrl = "https://oauth2.googleapis.com/tokeninfo?access_token=" + request.getAccessToken();
            GoogleTokenResponse tokenResponse = restTemplate.getForObject(tokenInfoUrl, GoogleTokenResponse.class);

            if (tokenResponse == null || tokenResponse.getError() != null) {
                System.out.println("Token do Google inválido: "
                        + (tokenResponse != null ? tokenResponse.getError() : "Resposta nula"));
                return ResponseEntity.status(HttpStatus.UNAUTHORIZED).body("Invalid Google token");
            }

            if (!"911266742263-jm27q7p4v862mdic2p7ntacmpocutat8.apps.googleusercontent.com"
                    .equals(tokenResponse.getAudience())) {
                System.out.println("Audience inválida: " + tokenResponse.getAudience());
                return ResponseEntity.status(HttpStatus.UNAUTHORIZED).body("Invalid audience");
            }

            String email = tokenResponse.getEmail();
            String name = tokenResponse.getName();

            User user = userService.findByEmail(email);
            if (user == null) {
                user = userService.saveGoogleUser(email, name);
                System.out.println("Novo usuário Google registrado: " + email);
            }

            String token = jwtUtil.generateToken(email);
            System.out.println("Token gerado para Google login: " + token);
            return ResponseEntity.ok("{\"token\": \"" + token + "\"}");
        } catch (Exception e) {
            System.out.println("Erro no login com Google: " + e.getMessage());
            return ResponseEntity.status(HttpStatus.INTERNAL_SERVER_ERROR).body("Error: " + e.getMessage());
        }
    }

    // Login com Apple (já existente)
    @PostMapping("/apple-login")
    public ResponseEntity<String> loginWithApple(@RequestBody AppleLoginRequest request) {
        System.out.println("Tentativa de login com Apple: " + request.getIdentityToken());
        try {
            JwtParserBuilder parserBuilder = Jwts.parser();
            parserBuilder.setSigningKeyResolver(new AppleSigningKeyResolver());
            Jws<Claims> jwt = parserBuilder.build().parseClaimsJws(request.getIdentityToken());

            Claims claims = jwt.getBody();
            String email = claims.get("email", String.class);
            String appleId = claims.getSubject();

            User user = userService.findByEmail(email);
            if (user == null) {
                user = userService.saveAppleUser(email, appleId);
                System.out.println("Novo usuário Apple registrado: " + email);
            }

            String token = jwtUtil.generateToken(email);
            System.out.println("Token gerado para Apple login: " + token);
            return ResponseEntity.ok("{\"token\": \"" + token + "\"}");
        } catch (Exception e) {
            System.out.println("Erro no login com Apple: " + e.getMessage());
            return ResponseEntity.status(HttpStatus.INTERNAL_SERVER_ERROR).body("Error: " + e.getMessage());
        }
    }

    // Login com LinkedIn
    @PostMapping("/linkedin-login")
    public ResponseEntity<String> loginWithLinkedIn(@RequestBody LinkedInLoginRequest request) {
        System.out.println("Tentativa de login com LinkedIn: " + request.getAccessToken());
        try {
            // Validar o token com a API do LinkedIn
            String userInfoUrl = "https://api.linkedin.com/v2/userinfo";
            LinkedInUserResponse userResponse = restTemplate.getForObject(
                    userInfoUrl + "?oauth2_access_token=" + request.getAccessToken(),
                    LinkedInUserResponse.class);

            if (userResponse == null || userResponse.getEmail() == null) {
                System.out.println("Token do LinkedIn inválido ou resposta nula");
                return ResponseEntity.status(HttpStatus.UNAUTHORIZED).body("Invalid LinkedIn token");
            }

            String email = userResponse.getEmail();
            String name = userResponse.getName();

            User user = userService.findByEmail(email);
            if (user == null) {
                user = userService.saveLinkedInUser(email, name);
                System.out.println("Novo usuário LinkedIn registrado: " + email);
            }

            String token = jwtUtil.generateToken(email);
            System.out.println("Token gerado para LinkedIn login: " + token);
            return ResponseEntity.ok("{\"token\": \"" + token + "\"}");
        } catch (Exception e) {
            System.out.println("Erro no login com LinkedIn: " + e.getMessage());
            return ResponseEntity.status(HttpStatus.INTERNAL_SERVER_ERROR).body("Error: " + e.getMessage());
        }
    }

    // Login com GitHub
    @PostMapping("/github-login")
    public ResponseEntity<String> loginWithGitHub(@RequestBody GitHubLoginRequest request) {
        System.out.println("Tentativa de login com GitHub: " + request.getAccessToken());
        try {
            // Validar o token com a API do GitHub
            String userInfoUrl = "https://api.github.com/user";
            GitHubUserResponse userResponse = restTemplate.getForObject(
                    userInfoUrl,
                    GitHubUserResponse.class,
                    new java.util.HashMap<String, String>() {
                        {
                            put("Authorization", "Bearer " + request.getAccessToken());
                        }
                    });

            if (userResponse == null || userResponse.getEmail() == null) {
                System.out.println("Token do GitHub inválido ou resposta nula");
                return ResponseEntity.status(HttpStatus.UNAUTHORIZED).body("Invalid GitHub token");
            }

            String email = userResponse.getEmail();
            String name = userResponse.getLogin();

            User user = userService.findByEmail(email);
            if (user == null) {
                user = userService.saveGitHubUser(email, name);
                System.out.println("Novo usuário GitHub registrado: " + email);
            }

            String token = jwtUtil.generateToken(email);
            System.out.println("Token gerado para GitHub login: " + token);
            return ResponseEntity.ok("{\"token\": \"" + token + "\"}");
        } catch (Exception e) {
            System.out.println("Erro no login com GitHub: " + e.getMessage());
            return ResponseEntity.status(HttpStatus.INTERNAL_SERVER_ERROR).body("Error: " + e.getMessage());
        }
    }
}

// Classes de Request e Response
class GoogleLoginRequest {
    private String accessToken;

    public String getAccessToken() {
        return accessToken;
    }

    public void setAccessToken(String accessToken) {
        this.accessToken = accessToken;
    }
}

class AppleLoginRequest {
    private String identityToken;

    public String getIdentityToken() {
        return identityToken;
    }

    public void setIdentityToken(String identityToken) {
        this.identityToken = identityToken;
    }
}

class LinkedInLoginRequest {
    private String accessToken;

    public String getAccessToken() {
        return accessToken;
    }

    public void setAccessToken(String accessToken) {
        this.accessToken = accessToken;
    }
}

class GitHubLoginRequest {
    private String accessToken;

    public String getAccessToken() {
        return accessToken;
    }

    public void setAccessToken(String accessToken) {
        this.accessToken = accessToken;
    }
}

class GoogleTokenResponse {
    private String audience;
    private String email;
    private String name;
    private String error;

    public String getAudience() {
        return audience;
    }

    public void setAudience(String audience) {
        this.audience = audience;
    }

    public String getEmail() {
        return email;
    }

    public void setEmail(String email) {
        this.email = email;
    }

    public String getName() {
        return name;
    }

    public void setName(String name) {
        this.name = name;
    }

    public String getError() {
        return error;
    }

    public void setError(String error) {
        this.error = error;
    }
}

class LinkedInUserResponse {
    private String email;
    private String name;

    public String getEmail() {
        return email;
    }

    public void setEmail(String email) {
        this.email = email;
    }

    public String getName() {
        return name;
    }

    public void setName(String name) {
        this.name = name;
    }
}

class GitHubUserResponse {
    private String login;
    private String email;

    public String getLogin() {
        return login;
    }

    public void setLogin(String login) {
        this.login = login;
    }

    public String getEmail() {
        return email;
    }

    public void setEmail(String email) {
        this.email = email;
    }
}

class AppleSigningKeyResolver implements SigningKeyResolver {
    private final org.apache.http.client.HttpClient httpClient = org.apache.http.impl.client.HttpClients
            .createDefault();

    @Override
    public PublicKey resolveSigningKey(io.jsonwebtoken.JwsHeader header, Claims claims) {
        try {
            String kid = header.getKeyId();
            org.apache.http.client.methods.HttpGet request = new org.apache.http.client.methods.HttpGet(
                    "https://appleid.apple.com/auth/keys");
            org.apache.http.HttpResponse response = httpClient.execute(request);
            String jsonResponse = org.apache.http.util.EntityUtils.toString(response.getEntity());

            org.json.JSONObject keys = new org.json.JSONObject(jsonResponse);
            org.json.JSONArray keyArray = keys.getJSONArray("keys");
            for (int i = 0; i < keyArray.length(); i++) {
                org.json.JSONObject key = keyArray.getJSONObject(i);
                if (kid.equals(key.getString("kid"))) {
                    String n = key.getString("n");
                    String e = key.getString("e");
                    return generatePublicKey(n, e);
                }
            }
            throw new RuntimeException("Apple key not found");
        } catch (Exception e) {
            throw new RuntimeException("Failed to resolve Apple signing key", e);
        }
    }

    @Override
    public PublicKey resolveSigningKey(io.jsonwebtoken.JwsHeader header, byte[] content) {
        throw new UnsupportedOperationException("Apple Signing Key Resolver does not support raw content signing keys");
    }

    private PublicKey generatePublicKey(String modulus, String exponent) throws Exception {
        java.math.BigInteger n = new java.math.BigInteger(1, java.util.Base64.getUrlDecoder().decode(modulus));
        java.math.BigInteger e = new java.math.BigInteger(1, java.util.Base64.getUrlDecoder().decode(exponent));
        java.security.spec.RSAPublicKeySpec spec = new java.security.spec.RSAPublicKeySpec(n, e);
        java.security.KeyFactory factory = java.security.KeyFactory.getInstance("RSA");
        return factory.generatePublic(spec);
    }
}