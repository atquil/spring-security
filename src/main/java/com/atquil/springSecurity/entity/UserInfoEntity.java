package com.atquil.springSecurity.entity;

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
@Table(name="USER_INFO")
public class UserInfoEntity {
    @Id
    @GeneratedValue
    private Long id;

    @Column(name = "USER_NAME")
    private String userName;


    @Column(nullable = false, name = "EMAIL_ID", unique = true)
    private String emailId;

    @Column(name = "MOBILE_NUMBER")
    private String mobileNumber;

    @Column(nullable = false, name = "ROLES")
    private String roles;

    @Column(nullable = false, name = "PASSWORD")
    private String password;

    @OneToMany(mappedBy = "user", cascade = CascadeType.ALL, fetch = FetchType.LAZY)
    private List<RefreshTokenEntity> refreshTokens;
}

