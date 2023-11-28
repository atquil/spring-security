package com.atquil.springSecurity.controller;

import com.atquil.springSecurity.service.UserInfoService;
import lombok.RequiredArgsConstructor;
import org.springframework.http.ResponseEntity;
import org.springframework.security.core.Authentication;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

/**
 * @author atquil
 */
@RestController
@RequestMapping("/api")
@RequiredArgsConstructor
public class WelcomePageController {

    private final UserInfoService userInfoService;
    @GetMapping("/welcome-message")
    public ResponseEntity<String> getFirstWelcomeMessage(){
            // Return all user
        return ResponseEntity.ok("Welcome to the tutorial");
    }

    @GetMapping("/all-user")
    public ResponseEntity<?> getAllUserDetails(){
        // Return all user
      //  System.out.println("Auth"+authentication.getName());
        return ResponseEntity.ok(userInfoService.getAllUserDetails());
    }
}
