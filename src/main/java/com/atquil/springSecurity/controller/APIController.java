package com.atquil.springSecurity.controller;

import jakarta.annotation.security.RolesAllowed;
import org.springframework.http.ResponseEntity;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import java.util.ResourceBundle;

/**
 * @author atquil
 */

@RestController
@RequestMapping("/api")
public class APIController {

    @GetMapping("/dummy")
    public ResponseEntity<String> getDummyData(){
        return ResponseEntity.ok("Returning dummy data");
    }


    @PreAuthorize("hasRole('ADMIN')")
    @GetMapping("/dummy/admin")
    public ResponseEntity<String> getDummyDataForAdmin(){
        return ResponseEntity.ok("Admin: Dummy data");
    }
}
