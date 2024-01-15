package com.atquil.springSecurity.repo;

import com.atquil.springSecurity.entities.RefreshTokenEntity;
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
public interface RefreshTokenRepo extends JpaRepository<RefreshTokenEntity,Long> {


    Optional<RefreshTokenEntity> findByRefreshToken(String refreshToken);



    @Query(value = "SELECT rt.* FROM REFRESH_TOKENS rt " +
            "INNER JOIN USER_DETAILS ud ON rt.user_id = ud.id " +
            "WHERE ud.EMAIL = :userEmail and (rt.expired = false or rt.revoked = false )", nativeQuery = true)
    List<RefreshTokenEntity> findByUserEmailId(@Param("userEmail") String userEmail);

}
