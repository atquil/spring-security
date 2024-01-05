package com.atquil.springSecurity.controller;

import com.atquil.springSecurity.config.JWTConfig.TokenGenerator;
import com.atquil.springSecurity.dto.UserRegistrationDto;
import com.atquil.springSecurity.service.UserInfoService;
import jakarta.validation.Valid;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.context.support.DefaultMessageSourceResolvable;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.security.core.Authentication;
import org.springframework.validation.BindingResult;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RestController;

import java.util.List;

/**
 * @author atquil
 */


@RestController
@RequiredArgsConstructor
@Slf4j
public class AuthController {

    private final UserInfoService userInfoService;
    private final TokenGenerator tokenGenerator;

    @PostMapping("/signup")
    public ResponseEntity<?> registerUser(@Valid @RequestBody UserRegistrationDto userRegistrationDto,
                                          BindingResult bindingResult){
        if (bindingResult.hasErrors()) {
            List<String> errorMessage = bindingResult.getAllErrors().stream()
                    .map(DefaultMessageSourceResolvable::getDefaultMessage)
                    .toList();
            return ResponseEntity.status(HttpStatus.BAD_REQUEST).body(errorMessage);
        }
        return ResponseEntity.ok(userInfoService.registerUser(userRegistrationDto));
    }

   // @PreAuthorize("hasAnyRole('ROLE_MANAGER','ROLE_ADMIN')")
    @GetMapping ("/signin")
    public ResponseEntity<String> authenticateUser(Authentication authentication){
        System.out.println("Role"+authentication.getAuthorities());
        return ResponseEntity.ok(tokenGenerator.generateAccessTOKEN(authentication));
    }


}
