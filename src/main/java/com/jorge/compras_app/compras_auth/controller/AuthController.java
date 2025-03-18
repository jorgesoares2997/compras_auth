package com.jorge.compras_app.compras_auth.controller;

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
@CrossOrigin(origins = "http://localhost:3000")
public class AuthController {

    @Autowired
    private UserService userService;

    @Autowired
    private JwtUtil jwtUtil;

    // Redirecionamento manual para iniciar o fluxo OAuth
    @GetMapping("/{provider}/login")
    public ResponseEntity<Void> redirectToProvider(@PathVariable String provider) {
        String redirectUrl = OAuth2AuthorizationRequestRedirectFilter.DEFAULT_AUTHORIZATION_REQUEST_BASE_URI + "/"
                + provider;
        return ResponseEntity.status(HttpStatus.FOUND).header("Location", redirectUrl).build();
    }

    // Callback para Google
    @GetMapping("/google/callback")
    public ResponseEntity<String> googleCallback(
            @RegisteredOAuth2AuthorizedClient("google") OAuth2AuthorizedClient authorizedClient) {
        String email = authorizedClient.getPrincipalName();
        String name = (String) authorizedClient.getAccessToken().getTokenValue(); // Simplificado
        return processSocialLogin(email, name, "google");
    }

    // Callback para LinkedIn
    @GetMapping("/linkedin/callback")
    public ResponseEntity<String> linkedinCallback(
            @RegisteredOAuth2AuthorizedClient("linkedin") OAuth2AuthorizedClient authorizedClient) {
        String email = authorizedClient.getPrincipalName();
        String name = (String) authorizedClient.getAccessToken().getTokenValue(); // Simplificado
        return processSocialLogin(email, name, "linkedin");
    }

    // Callback para GitHub
    @GetMapping("/github/callback")
    public ResponseEntity<String> githubCallback(
            @RegisteredOAuth2AuthorizedClient("github") OAuth2AuthorizedClient authorizedClient) {
        String email = authorizedClient.getPrincipalName();
        String name = (String) authorizedClient.getAccessToken().getTokenValue(); // Simplificado
        return processSocialLogin(email, name, "github");
    }

    // Callback para Apple
    @GetMapping("/apple/callback")
    public ResponseEntity<String> appleCallback(
            @RegisteredOAuth2AuthorizedClient("apple") OAuth2AuthorizedClient authorizedClient) {
        String email = authorizedClient.getPrincipalName();
        String name = (String) authorizedClient.getAccessToken().getTokenValue(); // Simplificado
        return processSocialLogin(email, name, "apple");
    }

    private ResponseEntity<String> processSocialLogin(String email, String name, String provider) {
        User user = userService.findByEmail(email);
        if (user == null) {
            user = userService.saveSocialUser(email, name, provider);
            System.out.println("Novo usuário " + provider + " registrado: " + email);
        }
        String token = jwtUtil.generateToken(email);
        System.out.println("Token gerado para " + provider + " login: " + token);
        return ResponseEntity.ok("{\"token\": \"" + token + "\"}");
    }
}