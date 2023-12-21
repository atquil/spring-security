package com.atquil.springSecurity.controller;

import org.springframework.http.ResponseEntity;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import java.security.Principal;

/**
 * @author atquil
 */
@RequestMapping("/api")
@RestController
public class UserController {

    @GetMapping("/anyone")
    public ResponseEntity<?> getTestAPI(){
        return ResponseEntity.ok("Anyone can access me");
    }

    @PreAuthorize("hasAnyRole('ROLE_MANAGER','ROLE_ADMIN')")
    @GetMapping("/manager")
    public ResponseEntity<?> getTestAPI2(Principal principal){

        return ResponseEntity.ok(principal.getName()+": has logged in.");
    }

    @PreAuthorize("hasRole('ROLE_ADMIN')")
    @GetMapping("/admin")
    public ResponseEntity<?> getTestAPI3(Principal principal){
        return ResponseEntity.ok("User:"+principal.getName()+" is an owner");
    }
}

