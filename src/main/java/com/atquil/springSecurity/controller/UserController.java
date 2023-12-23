package com.atquil.springSecurity.controller;

import com.atquil.springSecurity.repo.UserRepo;
import lombok.RequiredArgsConstructor;
import org.springframework.http.ResponseEntity;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import java.security.Principal;

/**
 * @author atquil
 */
@RestController
@RequestMapping("/api")
@RequiredArgsConstructor
public class UserController {

    private final UserRepo userRepo;

    @GetMapping("/anyone")
    public ResponseEntity<?> getTestAPI1(){
        return ResponseEntity.ok("Response");
    }


    @PreAuthorize("hasAnyRole('ROLE_MANAGER','ROLE_ADMIN')")
    @GetMapping("/manager")
    public ResponseEntity<?> getTestAPI2(Principal principal){

        return ResponseEntity.ok(principal.getName()+" : All data from backend"+ userRepo.findAll());
    }


    @PreAuthorize("hasRole('ROLE_ADMIN')")
    @GetMapping("/admin")
    public ResponseEntity<?> getTestAPI3(Principal principal){
        return ResponseEntity.ok("User:"+principal.getName()+" is an owner");
    }
}
