package com.atquil.springSecurity.controller;

import com.atquil.springSecurity.service.JWTTokenService;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.security.core.Authentication;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RestController;

/**
 * @author atquil
 */

@RestController
@Slf4j
@RequiredArgsConstructor
public class AuthController {


    private final JWTTokenService jwtTokenService;

    @PostMapping("/token")
    public String token(Authentication authentication) {
        log.debug("Token requested for user: '{}'", authentication.getName());
        String token = jwtTokenService.generateToken(authentication);
        log.debug("Token granted: {}", token);
        return token;
    }
}
