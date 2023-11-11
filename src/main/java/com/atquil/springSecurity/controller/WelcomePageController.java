package com.atquil.springSecurity.controller;

import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RestController;

/**
 * @author atquil
 */
@RestController
public class WelcomePageController {

    @GetMapping("/welcome-message")
    public ResponseEntity<String> getFirstWelcomeMessage(){

        return ResponseEntity.ok("Welcome to the tutorial");
    }
}
