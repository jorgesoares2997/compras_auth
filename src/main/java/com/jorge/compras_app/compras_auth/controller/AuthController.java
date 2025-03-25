package com.jorge.compras_app.compras_auth.controller;

import java.util.Base64;

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

@RestController
@RequestMapping("/api/auth")
@CrossOrigin(origins = { "http://localhost:3000" }, allowCredentials = "true")
public class AuthController {

    @Autowired
    private UserService userService;

    @Autowired
    private JwtUtil jwtUtil;

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

    @GetMapping("/github/callback")
    public ResponseEntity<Void> githubCallback(
            @RegisteredOAuth2AuthorizedClient("github") OAuth2AuthorizedClient authorizedClient,
            @RequestParam(required = false) String state) {
        return processCallback(authorizedClient, "github", state);
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

        // Redireciona para o frontend com o token e state
        String redirectUrl = "http://localhost:3000/contact?token=" + token + "&state="
                + (state != null ? state : "");
        return ResponseEntity.status(HttpStatus.FOUND).header("Location", redirectUrl).build();
    }

    private String encodeState(String name, String email, String message) {
        return Base64.getUrlEncoder().encodeToString((name + "|" + email + "|" + message).getBytes());
    }
}