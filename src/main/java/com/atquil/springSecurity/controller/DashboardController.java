package com.atquil.springSecurity.controller;

import jakarta.annotation.security.RolesAllowed;
import lombok.RequiredArgsConstructor;
import org.springframework.http.ResponseEntity;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.security.core.Authentication;
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
public class DashboardController {

    @GetMapping("/welcome-message")
    public ResponseEntity<String> getFirstWelcomeMessage(Authentication authentication){
        return ResponseEntity.ok("Welcome to the JWT Tutorial:"+authentication.getName()+"with scope:"+authentication.getAuthorities());

    }

    //@PreAuthorize("hasRole('ROLE_ADMIN')")
    @PreAuthorize("hasAuthority('SCOPE_READ')")
    @GetMapping("/admin-message")
    public ResponseEntity<String> getAdminData(Principal principal){
        return ResponseEntity.ok("Admin::"+principal.getName());

    }
}
