package com.atquil.springSecurity.controller;

import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import java.security.Principal;

/**
 * @author atquil
 */

@RestController
@RequestMapping("/api")
public class APIController {

    @GetMapping("/dummy")
    public ResponseEntity<String> getResponse(){
        return ResponseEntity.ok("I am getting response");
    }

    @GetMapping("/dummy/user-detail")
    public ResponseEntity<String> getUserDetails(Principal principal){
        return ResponseEntity.ok(principal.getName() +" Is the user");
    }
}
