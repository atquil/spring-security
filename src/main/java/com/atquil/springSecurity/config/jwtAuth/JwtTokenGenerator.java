package com.atquil.springSecurity.config.jwtAuth;

import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.oauth2.jwt.JwtClaimsSet;
import org.springframework.security.oauth2.jwt.JwtEncoder;
import org.springframework.security.oauth2.jwt.JwtEncoderParameters;
import org.springframework.stereotype.Service;

import java.time.Instant;
import java.time.temporal.ChronoUnit;
import java.util.HashSet;
import java.util.List;
import java.util.Set;
import java.util.stream.Collectors;

/**
 * @author atquil
 */

@Service
@RequiredArgsConstructor
@Slf4j
public class JwtTokenGenerator {


    private final JwtEncoder jwtEncoder;

    public String generateAccessToken(Authentication authentication) {

        log.info("[JwtTokenGenerator:generateAccessToken] Token Creation Started for:{}", authentication.getName());

        String roles = getRoles(authentication);

        String permissions = getPermissionsFromRoles(roles);

        JwtClaimsSet claims = getJwtClaimsSet(
                15,
                ChronoUnit.MINUTES,
                authentication,
                permissions);

        return getTokenValue(claims);
    }

    public String generateRefreshToken(Authentication authentication) {
        log.info("[JwtTokenGenerator:generateRefreshToken] Token Creation Started for:{}",authentication.getName());

        JwtClaimsSet claims = getJwtClaimsSet(
                60,
                ChronoUnit.DAYS,
                authentication,
                "REFRESH_TOKEN");
        return getTokenValue(claims);
    }

    private static String getRoles(Authentication authentication) {
        return authentication.getAuthorities().stream()
                .map(GrantedAuthority::getAuthority)
                .collect(Collectors.joining(" "));
    }

    private static JwtClaimsSet getJwtClaimsSet(int duration,
                                                ChronoUnit chronoUnit,
                                                Authentication authentication,
                                                String scope) {
        return JwtClaimsSet.builder()
                .issuer("atquil")
                .issuedAt(Instant.now())
                .expiresAt(Instant.now().plus(duration, chronoUnit)) // Minutes
                .subject(authentication.getName())
                .claim("scope", scope) // whatever we have fixed the authority
                .build();
    }

    private String getTokenValue(JwtClaimsSet claims) {
        return this.jwtEncoder.encode(JwtEncoderParameters.from(claims)).getTokenValue();
    }

    //Permissions for jwt
    private String getPermissionsFromRoles(String roles) {
        Set<String> permissions = new HashSet<>();

        if (roles.contains("ROLE_ADMIN")) {
            permissions.addAll(List.of("READ", "WRITE", "DELETE"));
        }
        if (roles.contains("ROLE_MANAGER")) {
            permissions.addAll(List.of("READ"));
        }
        if (roles.contains("ROLE_USER")) {
            permissions.add("READ");
        }

        return String.join(" ", permissions);
    }

}
