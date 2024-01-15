package com.atquil.springSecurity.controller;

import com.atquil.springSecurity.config.JWTConfig.TokenGenerator;
import com.atquil.springSecurity.dto.UserRegistrationDto;
import com.atquil.springSecurity.service.UserInfoService;
import jakarta.validation.Valid;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.context.support.DefaultMessageSourceResolvable;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.security.core.Authentication;
import org.springframework.validation.BindingResult;
import org.springframework.web.bind.annotation.*;

import java.util.List;

/**
 * @author atquil
 */


@RestController
@RequiredArgsConstructor
@Slf4j
public class AuthController {

    private final UserInfoService userInfoService;

    @PostMapping("/signup")
    public ResponseEntity<?> registerUser(@Valid @RequestBody UserRegistrationDto userRegistrationDto,
                                          BindingResult bindingResult){

        log.info("Signup Process Started for user:{}",userRegistrationDto.userName());
        if (bindingResult.hasErrors()) {
            List<String> errorMessage = bindingResult.getAllErrors().stream()
                    .map(DefaultMessageSourceResolvable::getDefaultMessage)
                    .toList();
            log.error("Biding Result has error:{}",errorMessage);
            return ResponseEntity.status(HttpStatus.BAD_REQUEST).body(errorMessage);
        }
        return ResponseEntity.ok(userInfoService.registerUser(userRegistrationDto));
    }

   // @PreAuthorize("hasAnyRole('ROLE_MANAGER','ROLE_ADMIN')")
    @GetMapping ("/signin")
    public ResponseEntity<?> authenticateUser(Authentication authentication){
        System.out.println("Role"+authentication.getAuthorities());
        //return ResponseEntity.ok(tokenGenerator.generateAccessToken(authentication));
        return ResponseEntity.ok(userInfoService.authenticateUser(authentication));
    }


    @PostMapping ("/refresh-token")
    public ResponseEntity<?> getAccessToken(@RequestHeader(HttpHeaders.AUTHORIZATION) String authorizationHeader){
        return ResponseEntity.ok(userInfoService.getAccessTokenUsingRefreshToken(authorizationHeader));
    }

    @PostMapping ("/logout")
    public ResponseEntity<?> logoutUser(){

        return ResponseEntity.ok("userInfoService.revokeRefreshTokensForUser(authentication.getName()");
    }


}
