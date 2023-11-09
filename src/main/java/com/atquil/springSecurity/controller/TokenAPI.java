package com.atquil.springSecurity.controller;

import com.atquil.springSecurity.config.TokenGenerator;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.http.ResponseEntity;
import org.springframework.security.core.Authentication;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RestController;

/**
 * @author atquil
 */
@RestController
@Slf4j
@RequiredArgsConstructor
public class TokenAPI {

    private final TokenGenerator tokenGenerator;

    @PostMapping("/token")
    public ResponseEntity<String> generateJWTToken(Authentication authentication){
        //This api will take value from basic authentication, and generate the token
        String token = tokenGenerator.generateToken(authentication);
        log.info("Token generated for {} :  {}", authentication.getName(),token);
        return ResponseEntity.ok(token);
    }
}
