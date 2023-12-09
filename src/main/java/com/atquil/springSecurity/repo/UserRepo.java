package com.atquil.springSecurity.repo;

import com.atquil.springSecurity.entity.UserEntity;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.stereotype.Repository;

import java.util.Optional;

/**
 * @author atquil
 */

@Repository
public interface UserRepo  extends JpaRepository<UserEntity,Long> {
    Optional<UserEntity> findByUsername(String username);
}

