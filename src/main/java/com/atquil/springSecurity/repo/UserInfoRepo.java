package com.atquil.springSecurity.repo;

import com.atquil.springSecurity.entities.UserInfoEntity;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.stereotype.Repository;

import java.util.Optional;

/**
 * @author atquil
 */
@Repository
public interface UserInfoRepo extends JpaRepository<UserInfoEntity,String> {
    Optional<UserInfoEntity> findByEmailId(String userEmailId);
}
