package com.atquil.springSecurity.repo;

import com.atquil.springSecurity.entities.UserDetailsEntity;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.Query;
import org.springframework.data.repository.query.Param;
import org.springframework.stereotype.Repository;

import java.util.List;
import java.util.Optional;

/**
 * @author atquil
 */
@Repository
public interface UserDetailsRepo extends JpaRepository<UserDetailsEntity,Long> {
    Optional<UserDetailsEntity> findByEmailId(String userEmailId);


    @Query(value = "SELECT ud.* FROM USER_DETAILS ud  " +
            "LEFT JOIN REFRESH_TOKENS rt ON rt.user_id = ud.id " , nativeQuery = true)
    List<UserDetailsEntity> findAllUserDetailsEntity();

}
