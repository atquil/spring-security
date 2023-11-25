package com.atquil.springSecurity.controller;

import com.atquil.springSecurity.config.TokenGenerator;
import com.atquil.springSecurity.dto.UserLoginUsingEmailDto;
import com.atquil.springSecurity.dto.UserRegistrationDto;
import com.atquil.springSecurity.service.UserInfoService;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.http.ResponseEntity;
import org.springframework.security.core.Authentication;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RestController;

/**
 * @author atquil
 */


@RestController
@RequiredArgsConstructor
@Slf4j
public class UserController {

    private final UserInfoService userInfoService;
    private final TokenGenerator tokenGenerator;

    @PostMapping("/register")
    public ResponseEntity<?> registerUser(@RequestBody UserRegistrationDto userRegistrationDto){
        return ResponseEntity.ok(userInfoService.registerUser(userRegistrationDto));
    }

    @PostMapping ("/login")
    public ResponseEntity<?> checkUserForLogin(@RequestBody UserLoginUsingEmailDto userLoginUsingEmailDto){
        return ResponseEntity.ok(userInfoService.getUserDetailsUsingEmail(userLoginUsingEmailDto));
    }

    @PostMapping("/token")
    public ResponseEntity<String> generateJWTToken(Authentication authentication){
        //This api will take value from basic authentication, and generate the token
        String token = tokenGenerator.generateToken(authentication);
        log.info("Token generated for {} :  {}", authentication.getName(),token);
        return ResponseEntity.ok(token);
    }


}
