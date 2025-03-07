package com.jorge.compras_app.compras_auth.repository;




import org.springframework.data.jpa.repository.JpaRepository;

import com.jorge.compras_app.compras_auth.model.User;

import java.util.Optional;

public interface UserRepository extends JpaRepository<User, Long> {
    Optional<User> findByEmail(String email);
}