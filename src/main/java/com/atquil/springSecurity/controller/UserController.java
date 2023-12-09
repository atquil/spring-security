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
@RequestMapping("/api/user")
@RestController
public class UserController {

    @GetMapping("/test1")
    public ResponseEntity<?> getTestAPI(){
        return ResponseEntity.ok("Response");
    }

    //Accessed only with the role USER
    @PreAuthorize("hasRole('ROLE_USER')")
    @GetMapping("/test2")
    public ResponseEntity<?> getTestAPI2(Principal principal){

        return ResponseEntity.ok(principal.getName()+": has logged in.");
    }
    //Accessed only with the role OWNER
    @PreAuthorize("hasRole('ROLE_OWNER')")
    @GetMapping("/test3")
    public ResponseEntity<?> getTestAPI3(Principal principal){
        return ResponseEntity.ok("User:"+principal.getName()+" is an owner");
    }
}

