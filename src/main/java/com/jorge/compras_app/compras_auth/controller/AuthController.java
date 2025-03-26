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
import com.jorge.compras_app.compras_auth.config.JwtUtil;
import com.jorge.compras_app.compras_auth.model.User;
import com.jorge.compras_app.compras_auth.service.UserService;
import com.jorge.compras_app.compras_auth.service.GitHubService;

@RestController
@RequestMapping("/api/auth")
@CrossOrigin(origins = { "http://localhost:3000" }, allowCredentials = "true")
public class AuthController {

    @Autowired
    private UserService userService;

    @Autowired
    private JwtUtil jwtUtil;

    @Autowired
    private GitHubService githubService;

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
            // Troca o código pelo token de acesso
            Map<String, Object> tokenResponse = githubService.getAccessToken(code).block();
            if (tokenResponse == null || !tokenResponse.containsKey("access_token")) {
                return ResponseEntity.status(HttpStatus.UNAUTHORIZED)
                        .body("Failed to get access token from GitHub");
            }

            String accessToken = (String) tokenResponse.get("access_token");

            // Obtém as informações do usuário
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
        String name = (String) authorizedClient.getAccessToken().getTokenValue(); // Simplificado
        User user = userService.findByEmail(email);
        if (user == null) {
            user = userService.saveSocialUser(email, name, provider);
            System.out.println("Novo usuário " + provider + " registrado: " + email);
        }
        String token = jwtUtil.generateToken(email);
        System.out.println("Token gerado para " + provider + " login: " + token);

        // Redireciona para o app Flutter com o token
        String redirectUrl = "comprasapp://oauth/callback?token=" + token;
        return ResponseEntity.status(HttpStatus.FOUND).header("Location", redirectUrl).build();
    }

    private String encodeState(String name, String email, String message) {
        return Base64.getUrlEncoder().encodeToString((name + "|" + email + "|" + message).getBytes());
    }
}