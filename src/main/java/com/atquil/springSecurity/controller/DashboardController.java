package com.atquil.springSecurity.controller;

import com.atquil.springSecurity.service.UserInfoService;
import lombok.RequiredArgsConstructor;
import org.springframework.http.ResponseEntity;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.security.oauth2.server.resource.authentication.JwtAuthenticationToken;
import org.springframework.web.bind.annotation.*;

/**
 * @author atquil
 */
@RestController
@RequestMapping("/api")
@RequiredArgsConstructor
public class DashboardController {

    private final UserInfoService userInfoService;
    @PreAuthorize("hasAnyAuthority('SCOPE_READ')")
    @GetMapping("/welcome-message")
    public ResponseEntity<String> getFirstWelcomeMessage(JwtAuthenticationToken jwtAuthenticationToken){
        return ResponseEntity.ok("Welcome to the tutorial");

    }
    @PreAuthorize("hasAnyAuthority('SCOPE_READ')")
    @PostMapping("/all-user")
    public ResponseEntity<?> getAllUserDetails(JwtAuthenticationToken jwtAuthenticationToken){
        return ResponseEntity.ok(userInfoService.getAllUserDetails());
    }
    @PreAuthorize("hasAnyAuthority('SCOPE_DELETE')")
    @DeleteMapping("/delete-user")
    public ResponseEntity<?> deleteUser(@RequestParam ("userEmail") String userEmail ){
        System.out.println("UserEmail"+userEmail);
        return ResponseEntity.ok(userInfoService.deleteUser(userEmail));
    }
}
