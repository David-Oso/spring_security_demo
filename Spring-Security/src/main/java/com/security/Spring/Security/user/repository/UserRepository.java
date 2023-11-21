package com.security.Spring.Security.user.repository;


import com.security.Spring.Security.user.model.User;
import org.springframework.data.jpa.repository.JpaRepository;

import java.util.Optional;

public interface UserRepository extends JpaRepository<User, Integer> {
    Optional<User> findUserByAppUser_Email(String email);

}
