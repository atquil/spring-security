package com.atquil.springSecurity.service;

import lombok.RequiredArgsConstructor;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.oauth2.jwt.JwtClaimsSet;
import org.springframework.security.oauth2.jwt.JwtEncoder;
import org.springframework.security.oauth2.jwt.JwtEncoderParameters;
import org.springframework.stereotype.Service;

import java.time.Instant;
import java.time.temporal.ChronoUnit;
import java.util.stream.Collectors;

/**
 * @author atquil
 */
@Service //Add the class in application context
@RequiredArgsConstructor //constructor injection
public class JWTTokenService {

    private final JwtEncoder jwtEncoder;

    public String generateToken(Authentication authentication) {
        Instant now = Instant.now();
        String scope = authentication.getAuthorities().stream()
                .map(GrantedAuthority::getAuthority)
                .collect(Collectors.joining(" "));
        JwtClaimsSet claims = JwtClaimsSet.builder()
                .issuer("self") //we are self signing the jwt
                .issuedAt(now)
                .expiresAt(now.plus(1, ChronoUnit.HOURS)) // expires in hour
                .subject(authentication.getName())
                .claim("scope", scope) // whatever we have fixed the authority
                .build();
        return this.jwtEncoder.encode(JwtEncoderParameters.from(claims)).getTokenValue();
    }
}
