package com.jorge.compras_app.compras_auth.controller;

import java.util.Base64;
import java.util.HashMap;
import java.util.Map;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.security.oauth2.client.OAuth2AuthorizedClient;
import org.springframework.security.oauth2.client.annotation.RegisteredOAuth2AuthorizedClient;
import org.springframework.security.oauth2.client.web.OAuth2AuthorizationRequestRedirectFilter;
import org.springframework.web.bind.annotation.*;
import org.springframework.web.multipart.MultipartFile;
import com.jorge.compras_app.compras_auth.config.JwtUtil;
import com.jorge.compras_app.compras_auth.model.User;
import com.jorge.compras_app.compras_auth.service.UserService;
import com.jorge.compras_app.compras_auth.service.GitHubService;

import java.io.File;
import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;

@RestController
@RequestMapping("/api/auth")
@CrossOrigin(origins = "*", allowCredentials = "true")
public class AuthController {

    @Autowired
    private UserService userService;

    @Autowired
    private JwtUtil jwtUtil;

    @Autowired
    private GitHubService githubService;

    // Diretório pra salvar as fotos (ajuste conforme necessário)
    private static final String UPLOAD_DIR = "uploads/";

    @GetMapping("/{provider}/login")
    public ResponseEntity<Void> redirectToProvider(@PathVariable String provider,
            @RequestParam String name, @RequestParam String email, @RequestParam String message) {
        String redirectUrl = OAuth2AuthorizationRequestRedirectFilter.DEFAULT_AUTHORIZATION_REQUEST_BASE_URI + "/"
                + provider
                + "?state=" + encodeState(name, email, message);
        return ResponseEntity.status(HttpStatus.FOUND).header("Location", redirectUrl).build();
    }

    @GetMapping("/google/callback")
    public ResponseEntity<Void> googleCallback(
            @RegisteredOAuth2AuthorizedClient("google") OAuth2AuthorizedClient authorizedClient,
            @RequestParam(required = false) String state) {
        return processCallback(authorizedClient, "google", state);
    }

    @GetMapping("/linkedin/callback")
    public ResponseEntity<Void> linkedinCallback(
            @RegisteredOAuth2AuthorizedClient("linkedin") OAuth2AuthorizedClient authorizedClient,
            @RequestParam(required = false) String state) {
        return processCallback(authorizedClient, "linkedin", state);
    }

    @GetMapping("/github/login")
    public ResponseEntity<?> githubLogin(@RequestParam String code) {
        try {
            Map<String, Object> tokenResponse = githubService.getAccessToken(code).block();
            if (tokenResponse == null || !tokenResponse.containsKey("access_token")) {
                return ResponseEntity.status(HttpStatus.UNAUTHORIZED)
                        .body("Failed to get access token from GitHub");
            }

            String accessToken = (String) tokenResponse.get("access_token");
            Map<String, Object> userInfo = githubService.getUserInfo(accessToken).block();
            if (userInfo == null) {
                return ResponseEntity.status(HttpStatus.UNAUTHORIZED)
                        .body("Failed to get user info from GitHub");
            }

            String email = (String) userInfo.get("email");
            String name = (String) userInfo.get("name");
            if (name == null) {
                name = (String) userInfo.get("login");
            }

            if (email == null) {
                return ResponseEntity.status(HttpStatus.BAD_REQUEST)
                        .body("GitHub account must have a public email");
            }

            User user = userService.findByEmail(email);
            if (user == null) {
                user = userService.saveSocialUser(email, name, "github");
                System.out.println("Novo usuário GitHub registrado: " + email);
            }

            String token = jwtUtil.generateToken(email);
            System.out.println("Token gerado para login GitHub: " + token);

            Map<String, String> response = new HashMap<>();
            response.put("token", token);
            return ResponseEntity.ok(response);
        } catch (Exception e) {
            System.out.println("Erro no login do GitHub: " + e.getMessage());
            return ResponseEntity.status(HttpStatus.INTERNAL_SERVER_ERROR)
                    .body("Error processing GitHub login: " + e.getMessage());
        }
    }

    @GetMapping("/apple/callback")
    public ResponseEntity<Void> appleCallback(
            @RegisteredOAuth2AuthorizedClient("apple") OAuth2AuthorizedClient authorizedClient,
            @RequestParam(required = false) String state) {
        return processCallback(authorizedClient, "apple", state);
    }

    private ResponseEntity<Void> processCallback(OAuth2AuthorizedClient authorizedClient, String provider,
            String state) {
        String email = authorizedClient.getPrincipalName();
        String name = (String) authorizedClient.getAccessToken().getTokenValue();
        User user = userService.findByEmail(email);
        if (user == null) {
            user = userService.saveSocialUser(email, name, provider);
            System.out.println("Novo usuário " + provider + " registrado: " + email);
        }
        String token = jwtUtil.generateToken(email);
        System.out.println("Token gerado para " + provider + " login: " + token);

        String redirectUrl = "comprasapp://oauth/callback?token=" + token;
        return ResponseEntity.status(HttpStatus.FOUND).header("Location", redirectUrl).build();
    }

    private String encodeState(String name, String email, String message) {
        return Base64.getUrlEncoder().encodeToString((name + "|" + email + "|" + message).getBytes());
    }

    // Pegar dados do perfil
    @GetMapping("/profile")
    public ResponseEntity<Map<String, Object>> getProfile(@RequestHeader("Authorization") String authHeader) {
        try {
            String token = authHeader.replace("Bearer ", "");
            String email = jwtUtil.extractEmail(token);
            User user = userService.findByEmail(email);
            if (user == null) {
                return ResponseEntity.status(HttpStatus.UNAUTHORIZED).body(null);
            }

            Map<String, Object> profile = new HashMap<>();
            profile.put("name", user.getName());
            profile.put("email", user.getEmail());
            profile.put("responsibilityLevel", user.getResponsibilityLevel());
            profile.put("photoUrl", user.getPhotoUrl());
            return ResponseEntity.ok(profile);
        } catch (Exception e) {
            System.out.println("Erro ao obter perfil: " + e.getMessage());
            return ResponseEntity.status(HttpStatus.INTERNAL_SERVER_ERROR)
                    .body(Map.of("error", "Erro ao obter perfil: " + e.getMessage()));
        }
    }

    @PutMapping("/profile")
    public ResponseEntity<String> updateProfile(
            @RequestHeader("Authorization") String authHeader,
            @RequestBody Map<String, Object> updates) {
        try {
            String token = authHeader.replace("Bearer ", "");
            String email = jwtUtil.extractEmail(token);
            User user = userService.findByEmail(email);
            if (user == null) {
                return ResponseEntity.status(HttpStatus.UNAUTHORIZED).body("Usuário não encontrado");
            }

            String photoUrl = updates.containsKey("photoUrl") ? (String) updates.get("photoUrl") : null;

            userService.updateUserProfile(email, null, photoUrl); // Name é null pra não alterar
            return ResponseEntity.ok("Foto de perfil atualizada com sucesso");
        } catch (Exception e) {
            System.out.println("Erro ao atualizar perfil: " + e.getMessage());
            return ResponseEntity.status(HttpStatus.INTERNAL_SERVER_ERROR)
                    .body("Erro ao atualizar perfil: " + e.getMessage());
        }
    }

    @PostMapping("/profile/photo")
    public ResponseEntity<Map<String, String>> uploadProfilePhoto(
            @RequestHeader("Authorization") String authHeader,
            @RequestParam("photo") MultipartFile photo) {
        try {
            String token = authHeader.replace("Bearer ", "");
            System.out.println("Token recebido: " + token);
            if (!jwtUtil.validateToken(token)) {
                System.out.println("Token inválido");
                return ResponseEntity.status(HttpStatus.FORBIDDEN).body(Map.of("error", "Token inválido"));
            }
            String email = jwtUtil.extractEmail(token);
            System.out.println("Email extraído: " + email);
            User user = userService.findByEmail(email);
            if (user == null) {
                return ResponseEntity.status(HttpStatus.UNAUTHORIZED).body(Map.of("error", "Usuário não encontrado"));
            }

            File uploadDir = new File(UPLOAD_DIR);
            if (!uploadDir.exists()) {
                uploadDir.mkdirs();
            }

            String fileName = email.replace("@", "_") + "_" + System.currentTimeMillis() + ".jpg";
            Path filePath = Paths.get(UPLOAD_DIR + fileName);
            Files.write(filePath, photo.getBytes());

            String photoUrl = "https://compras-auth.onrender.com/" + UPLOAD_DIR + fileName;
            userService.updateUserProfile(email, null, photoUrl);

            Map<String, String> response = new HashMap<>();
            response.put("photoUrl", photoUrl);
            return ResponseEntity.ok(response);
        } catch (IOException e) {
            System.out.println("Erro ao fazer upload da foto: " + e.getMessage());
            return ResponseEntity.status(HttpStatus.INTERNAL_SERVER_ERROR)
                    .body(Map.of("error", "Erro ao fazer upload da foto: " + e.getMessage()));
        }
    }
}