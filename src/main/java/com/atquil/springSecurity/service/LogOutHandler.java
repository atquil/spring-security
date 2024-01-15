package com.atquil.springSecurity.service;

import com.atquil.springSecurity.config.JWTConfig.RSAKeyRecord;
import com.atquil.springSecurity.repo.RefreshTokenRepo;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import lombok.RequiredArgsConstructor;
import org.springframework.http.HttpHeaders;
import org.springframework.security.core.Authentication;
import org.springframework.security.oauth2.jwt.Jwt;
import org.springframework.security.oauth2.jwt.JwtDecoder;
import org.springframework.security.oauth2.jwt.NimbusJwtDecoder;
import org.springframework.security.web.authentication.logout.LogoutHandler;
import org.springframework.stereotype.Service;

import java.util.concurrent.locks.Lock;

/**
 * @author atquil
 */
@Service
@RequiredArgsConstructor
public class LogOutHandler implements LogoutHandler {

    private final RSAKeyRecord rsaKeyRecord;
    private final RefreshTokenRepo refreshTokenRepo;
    @Override
    public void logout(HttpServletRequest request, HttpServletResponse response, Authentication authentication) {
        final String authHeader = request.getHeader(HttpHeaders.AUTHORIZATION);
        JwtDecoder jwtDecoder =  NimbusJwtDecoder.withPublicKey(rsaKeyRecord.rsaPublicKey()).build();
        // If the token is not Bearer, then we don't need to do any settings.
        if(!authHeader.startsWith("Bearer ")){
            return;
        }

        final String refreshToken = authHeader.substring(7);
        var storedRefreshToken = refreshTokenRepo.findByRefreshToken(refreshToken)
                .map(token->{
                    token.setExpired(true);
                    token.setRevoked(true);
                    refreshTokenRepo.save(token);
                    return token;
                })
                .orElse(null);





    }
}
