package com.security.Spring.Security.manager.repository;

import com.security.Spring.Security.manager.model.Manager;
import org.springframework.data.jpa.repository.JpaRepository;

public interface ManagerRepository extends JpaRepository<Manager, Integer> {
}
