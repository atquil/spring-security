package com.atquil.springSecurity.entities;

import jakarta.persistence.*;
import lombok.AllArgsConstructor;
import lombok.Data;
import lombok.NoArgsConstructor;

import java.util.List;

/**
 * @author atquil
 */

@Data
@NoArgsConstructor
@AllArgsConstructor
@Entity
@Table(name="USER_DETAILS")
public class UserDetailsEntity {

    @Id
    @GeneratedValue //It will find the best suitable match based on what kind of db we are using
    private Long id;

    @Column(name = "USER_NAME")
    private String userName;


    @Column(nullable = false, name = "EMAIL", unique = true)
    private String emailId;

    @Column(name = "MOBILE_NUMBER")
    private String mobileNumber;

    @Column(nullable = false, name = "ROLES")
    private String roles;

    @Column(nullable = false, name = "PASSWORD")
    private String password;

    // Many-to-One relationship with RefreshTokenEntity
    @OneToMany(mappedBy = "user", cascade = CascadeType.ALL, fetch = FetchType.LAZY)
    private List<RefreshTokenEntity> refreshTokens;
}
