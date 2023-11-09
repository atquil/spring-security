package com.atquil.springSecurity.controller;

import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.http.ResponseEntity;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.annotation.AuthenticationPrincipal;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

/**
 * @author atquil
 */

@RestController
@RequiredArgsConstructor
@Slf4j
@RequestMapping("/user")
public class UserAPI {

    @GetMapping("/details")
    public ResponseEntity<String> getResponse(Authentication authentication){
        return ResponseEntity.ok("I am the user"+authentication.getName()+ " and have scope:"+authentication.getAuthorities());
    }

}
