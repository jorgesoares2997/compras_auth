package com.jorge.compras_app.compras_auth.service;

import org.springframework.beans.factory.annotation.Value;
import org.springframework.core.ParameterizedTypeReference;
import org.springframework.stereotype.Service;
import org.springframework.web.reactive.function.client.WebClient;
import reactor.core.publisher.Mono;

import java.util.List;
import java.util.Map;

@Service
public class GitHubService {

    @Value("${spring.security.oauth2.client.registration.github.client-id}")
    private String clientId;

    @Value("${spring.security.oauth2.client.registration.github.client-secret}")
    private String clientSecret;

    private final WebClient webClient;

    public GitHubService() {
        this.webClient = WebClient.builder()
                .baseUrl("https://api.github.com")
                .build();
    }
    public Mono<Map<String, Object>> getAccessToken(String code) {
        return webClient.post()
                .uri("https://github.com/login/oauth/access_token")
                .header("Accept", "application/json")
                .bodyValue(Map.of(
                        "client_id", clientId,
                        "client_secret", clientSecret,
                        "code", code
                ))
                .retrieve()
                .bodyToMono(new ParameterizedTypeReference<Map<String, Object>>() {});
    }

    public Mono<Map<String, Object>> getUserInfo(String accessToken) {
        return webClient.get()
                .uri("/user")
                .headers(headers -> headers.setBearerAuth(accessToken))
                .retrieve()
                .bodyToMono(new ParameterizedTypeReference<Map<String, Object>>() {})
                .flatMap(userInfo -> {
                    // Se o email não estiver no objeto principal, tenta buscar da API de emails
                    if (userInfo.get("email") == null) {
                        return webClient.get()
                                .uri("/user/emails")
                                .headers(headers -> headers.setBearerAuth(accessToken))
                                .retrieve()
                                .bodyToMono(new ParameterizedTypeReference<List<Map<String, Object>>>() {})
                                .map(emails -> {
                                    // Procura pelo email principal ou primeiro email verificado
                                    for (Map<String, Object> email : emails) {
                                        if ((Boolean) email.get("primary") || (Boolean) email.get("verified")) {
                                            userInfo.put("email", email.get("email"));
                                            break;
                                        }
                                    }
                                    return userInfo;
                                });
                    }
                    return Mono.just(userInfo);
                });
    }
} 