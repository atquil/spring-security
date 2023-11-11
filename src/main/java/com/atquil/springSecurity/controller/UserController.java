package com.atquil.springSecurity.controller;

import com.atquil.springSecurity.dto.UserRegistrationDto;
import com.atquil.springSecurity.service.UserRegistrationService;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.http.ResponseEntity;
import org.springframework.validation.annotation.Validated;
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

    private final UserRegistrationService userRegistrationService;
    @PostMapping("/register")
    public ResponseEntity<?> registerUser(@RequestBody UserRegistrationDto userRegistrationDto){
        log.info("are you coming here:{}",userRegistrationDto);

        return ResponseEntity.ok(userRegistrationService.registerUser(userRegistrationDto));
    }
}
