package com.jorge.compras_app.compras_auth.model;

import jakarta.persistence.Entity;
import jakarta.persistence.GeneratedValue;
import jakarta.persistence.GenerationType;
import jakarta.persistence.Id;
import jakarta.persistence.Column;
import lombok.Data;

import java.time.LocalDateTime;

@Entity(name = "users")
@Data
public class User {
    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    private Long id;

    @Column(unique = true, nullable = false)
    private String email;

    @Column(nullable = true) // Permitir null para usuários de Google e Apple
    private String password;

    private String name;

    @Column(name = "apple_id", unique = true) // Campo opcional para ID da Apple
    private String appleId;

    @Column(name = "created_at")
    private LocalDateTime createdAt;

    @Column(name = "last_login")
    private LocalDateTime lastLogin;

    @Column(name = "provider")
    private String provider;

    @Column(name = "responsibility_level", nullable = false)
    private int responsibilityLevel = 3; // Valor padrão 3

    @Column(name = "photo_url")
    private String photoUrl; // URL da foto do perfil
}