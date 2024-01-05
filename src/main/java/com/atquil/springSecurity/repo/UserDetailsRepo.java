package com.atquil.springSecurity.repo;

import com.atquil.springSecurity.entities.UserDetailsEntity;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.stereotype.Repository;

import java.util.Optional;

/**
 * @author atquil
 */
@Repository
public interface UserDetailsRepo extends JpaRepository<UserDetailsEntity,Long> {
    Optional<UserDetailsEntity> findByEmailId(String userEmailId);

}
