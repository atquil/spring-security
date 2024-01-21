package com.atquil.springSecurity.controller;

import com.atquil.springSecurity.service.AdminService;
import jakarta.annotation.security.RolesAllowed;
import lombok.RequiredArgsConstructor;
import org.springframework.http.ResponseEntity;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.security.core.Authentication;
import org.springframework.web.bind.annotation.*;

import java.security.Principal;

/**
 * @author atquil
 */
@RestController
@RequestMapping("/api")
@RequiredArgsConstructor
public class DashboardController {
    private final AdminService adminService;
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

    @PreAuthorize("hasAuthority('SCOPE_WRITE')")
    @GetMapping("/revoke-access")
    public ResponseEntity<String> revokeAccessForUser(@RequestParam("userEmail") String userEmail){
        return ResponseEntity.ok(adminService.revokeRefreshTokensForUser(userEmail));

    }
}
