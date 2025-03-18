package com.jorge.compras_app.compras_auth.service;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;

import com.jorge.compras_app.compras_auth.model.User;
import com.jorge.compras_app.compras_auth.repository.UserRepository;

import java.time.LocalDateTime;
import java.util.UUID;

@Service
public class UserService implements UserDetailsService {

    @Autowired
    private UserRepository userRepository;

    @Autowired
    private PasswordEncoder passwordEncoder;

    public User saveUser(User user) throws IllegalArgumentException {
        if (userRepository.findByEmail(user.getEmail()).isPresent()) {
            throw new IllegalArgumentException("Email já está em uso");
        }
        if (user.getPassword() != null) { // Só codifica se a senha for fornecida
            user.setPassword(passwordEncoder.encode(user.getPassword()));
        }
        user.setCreatedAt(LocalDateTime.now());
        return userRepository.save(user);
    }

    public User findByEmail(String email) {
        return userRepository.findByEmail(email).orElse(null);
    }

    public User saveGoogleUser(String email, String name) {
        User existingUser = findByEmail(email);
        if (existingUser != null) {
            existingUser.setLastLogin(LocalDateTime.now());
            return userRepository.save(existingUser);
        }

        User user = new User();
        user.setEmail(email);
        user.setName(name);
        user.setPassword(null); // Sem senha para usuários Google
        user.setCreatedAt(LocalDateTime.now());
        System.out.println("Registrando novo usuário Google: " + email);
        return userRepository.save(user);
    }

    public User saveAppleUser(String email, String appleId) {
        User existingUser = findByEmail(email);
        if (existingUser != null) {
            existingUser.setLastLogin(LocalDateTime.now());
            return userRepository.save(existingUser);
        }

        User user = new User();
        user.setEmail(email);
        user.setName("Apple User");
        user.setPassword(null); // Sem senha para usuários Apple
        user.setAppleId(appleId); // Armazena o ID único da Apple
        user.setCreatedAt(LocalDateTime.now());
        System.out.println("Registrando novo usuário Apple: " + email);
        return userRepository.save(user);
    }

    @Override
    public UserDetails loadUserByUsername(String email) throws UsernameNotFoundException {
        User user = userRepository.findByEmail(email)
                .orElseThrow(() -> new UsernameNotFoundException("User not found"));
        String password = user.getPassword() != null ? user.getPassword() : ""; // Senha vazia se null
        return org.springframework.security.core.userdetails.User
                .withUsername(user.getEmail())
                .password(password)
                .roles("USER")
                .build();
    }

    public boolean validateCredentials(String email, String password) {
        System.out.println("Validando credenciais para: " + email);
        User user = userRepository.findByEmail(email).orElse(null);
        if (user == null) {
            System.out.println("Usuário não encontrado para: " + email);
            return false;
        }
        if (user.getPassword() == null) { // Usuários Google/Apple não têm senha
            System.out.println("Usuário sem senha registrada: " + email);
            return false;
        }
        boolean isValid = passwordEncoder.matches(password, user.getPassword());
        System.out.println(
                "Senha fornecida: " + password + ", Senha no banco: " + user.getPassword() + ", Válida: " + isValid);
        if (isValid) {
            user.setLastLogin(LocalDateTime.now());
            userRepository.save(user);
        }
        return isValid;
    }

    // UserService.java (exemplo)
    public User saveLinkedInUser(String email, String name) {
        User user = new User();
        user.setEmail(email);
        user.setName(name);
        user.setPassword("linkedin-auth-" + UUID.randomUUID().toString()); // Senha dummy
        return userRepository.save(user);
    }

    public User saveGitHubUser(String email, String name) {
        User user = new User();
        user.setEmail(email);
        user.setName(name);
        user.setPassword("github-auth-" + UUID.randomUUID().toString()); // Senha dummy
        return userRepository.save(user);
    }
}