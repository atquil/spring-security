package com.atquil.springSecurity.config.JWTConfig;

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
import java.util.ArrayList;
import java.util.HashSet;
import java.util.List;
import java.util.stream.Collectors;

/**
 * @author atquil
 */
@Service
@RequiredArgsConstructor
@Slf4j
public class TokenGenerator {

    private final JwtEncoder jwtEncoder;

    //In UI store it in HttpOnlyCookie
    //Access Token : To verify the user
    public String generateAccessTOKEN (Authentication authentication) {
        log.info("Creating token for:{}",authentication.getName());

        Instant now = Instant.now();

        //Okta uses Oauth2.0 for authentication and OpenId for authorization
        String roles = authentication.getAuthorities().stream()
                .map(GrantedAuthority::getAuthority)
                .collect(Collectors.joining(" "));

        //Extract Authorization
        String permissions = getPermissionsFromRoles(roles);


        JwtClaimsSet claims = JwtClaimsSet.builder()
                .issuer("atquil") //we are self signing the jwt
                .issuedAt(now)
                .expiresAt(now.plus(1, ChronoUnit.HOURS)) // expires in hour
                .subject(authentication.getName())
                .claim("scope", permissions) // whatever we have fixed the authority
                .build();
        return this.jwtEncoder.encode(JwtEncoderParameters.from(claims)).getTokenValue();
    }


    private String getPermissionsFromRoles(String roles) {
        List<String> permissions = new ArrayList<>();

        if (roles.contains("ROLE_ADMIN")) {
            permissions.addAll(List.of("READ", "WRITE", "DELETE"));
        }
        if (roles.contains("ROLE_MANAGER")) {
            permissions.addAll(List.of("READ", "WRITE"));
        }
        if (roles.contains("ROLE_USER")) {
            permissions.add("READ");
        }

        // Remove duplicates by converting the list to a set and back to a list
        List<String> uniquePermissions = new ArrayList<>(new HashSet<>(permissions));

        // Join the unique permissions into a space-separated string
        return String.join(" ", uniquePermissions);
    }
}