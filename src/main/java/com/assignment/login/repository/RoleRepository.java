package com.assignment.login.repository;

import java.util.Optional;

import com.assignment.login.models.ERole;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.stereotype.Repository;
import com.assignment.login.models.Role;
@Repository
public interface RoleRepository extends JpaRepository<Role, Long> {
    Optional<Role> findByName(ERole name);
}