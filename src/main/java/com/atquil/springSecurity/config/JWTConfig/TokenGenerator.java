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
    //Access RefreshTokenEntity : To verify the user
    public String generateAccessToken(Authentication authentication) {
        log.info("Creating token for:{}",authentication.getName());

        Instant now = Instant.now();

        //Okta uses Oauth2.0 for authentication and OpenId for authorization
        String roles = getRoles(authentication);

        //Extract Authorization
        String scope = getPermissionsFromRoles(roles);

        System.out.println("Scope:::"+scope);
        JwtClaimsSet claims = getJwtClaimsSet(now,
                1,
                ChronoUnit.HOURS,
                authentication,
                scope);


        return getTokenValue(claims);
    }

    public String generateRefreshToken(Authentication authentication) {
        log.info("Creating Refresh token:{}",authentication.getName());

        Instant now = Instant.now();

        // We will only have Roles to get new refreshToken
        String roles = getRoles(authentication);

        JwtClaimsSet claims = getJwtClaimsSet(now,
                30,
                ChronoUnit.DAYS,
                authentication,
                "");
        return getTokenValue(claims);
    }

    private static String getRoles(Authentication authentication) {
        return authentication.getAuthorities().stream()
                .map(GrantedAuthority::getAuthority)
                .collect(Collectors.joining(" "));
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

    private static JwtClaimsSet getJwtClaimsSet(Instant now,
                                                int amountToAdd,
                                                ChronoUnit timeUnit,
                                                Authentication authentication,
                                                String scope) {
        return JwtClaimsSet.builder()
                .issuer("atquil")
                .issuedAt(now)
                .expiresAt(now.plus(amountToAdd, timeUnit)) // Minutes|| Hours || Days
                .subject(authentication.getName())
                .claim("scope", scope) // whatever we have fixed the authority
                .build();
    }

    private String getTokenValue(JwtClaimsSet claims) {
        return this.jwtEncoder.encode(JwtEncoderParameters.from(claims)).getTokenValue();
    }







}