package com.atquil.springSecurity.config.JWTConfig;

import com.atquil.springSecurity.config.userConfig.UserSecurityConfig;
import com.atquil.springSecurity.repo.UserDetailsRepo;
import lombok.RequiredArgsConstructor;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.security.oauth2.jwt.Jwt;
import org.springframework.stereotype.Component;

import java.time.Instant;
import java.util.Objects;

/**
 * @author atquil
 */

@Component
@RequiredArgsConstructor
public class TokenUtils {



    public String getUserName(Jwt jwtToken){
        return jwtToken.getSubject();
    }

    public boolean isTokenValid(Jwt jwtToken,UserDetails userDetails){
        final String userName = getUserName(jwtToken);
        boolean isTokenExpired = getIfTokenIsExpired(jwtToken);
        boolean isTokenUserSameAsDatabase = userName.equals(userDetails.getUsername());
        //Check if userName from the database is same as Userdetails and if token has expired
        return !isTokenExpired  && isTokenUserSameAsDatabase;

    }

    private boolean getIfTokenIsExpired(Jwt jwtToken) {
        return Objects.requireNonNull(jwtToken.getExpiresAt()).isBefore(Instant.now());
    }

    private final UserDetailsRepo userDetailsRepo;
    public UserDetails userDetails(String emailId){
        return userDetailsRepo
                .findByEmailId(emailId)
                .map(UserSecurityConfig::new)
                .orElseThrow(()-> new UsernameNotFoundException("UserEmail: "+emailId+" does not exist"));
    }
}
