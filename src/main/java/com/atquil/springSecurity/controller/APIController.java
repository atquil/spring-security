package com.atquil.springSecurity.controller;

import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import java.security.Principal;

/**
 * @author atquil
 */

@RestController
public class APIController {

    @GetMapping
    public ResponseEntity<String> getOpenData(){
        return ResponseEntity.ok("Open Access");
    }

    @GetMapping("/oauth")
    public ResponseEntity<String> getOauthData(Principal principal){
        return ResponseEntity.ok("Secured Data accessed by "+principal.getName()
        );
    }
}
