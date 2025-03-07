package com.jorge.compras_app.compras_auth.controller;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;

import com.jorge.compras_app.compras_auth.config.JwtUtil;

import com.jorge.compras_app.compras_auth.model.User;
import com.jorge.compras_app.compras_auth.service.UserService;

@RestController
@RequestMapping("/api/auth")
@CrossOrigin(origins = "*")
public class AuthController {

    @Autowired
    private UserService userService;

    @Autowired
    private JwtUtil jwtUtil;

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
}