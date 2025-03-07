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
        user.setPassword(passwordEncoder.encode(user.getPassword()));
        user.setCreatedAt(LocalDateTime.now());
        return userRepository.save(user);
    }

    @Override
    public UserDetails loadUserByUsername(String email) throws UsernameNotFoundException {
        User user = userRepository.findByEmail(email)
                .orElseThrow(() -> new UsernameNotFoundException("User not found"));
        return org.springframework.security.core.userdetails.User
                .withUsername(user.getEmail())
                .password(user.getPassword())
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
        boolean isValid = passwordEncoder.matches(password, user.getPassword());
        System.out.println(
                "Senha fornecida: " + password + ", Senha no banco: " + user.getPassword() + ", Válida: " + isValid);
        if (isValid) {
            user.setLastLogin(LocalDateTime.now());
            userRepository.save(user);
        }
        return isValid;
    }
}