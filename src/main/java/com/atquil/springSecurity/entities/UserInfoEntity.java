package com.atquil.springSecurity.entities;

import jakarta.persistence.*;
import lombok.AllArgsConstructor;
import lombok.Data;
import lombok.Generated;
import lombok.NoArgsConstructor;

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
    @GeneratedValue(strategy= GenerationType.UUID) //It will find the best suitable match based on what kind of db we are using
    private String id;

    @Column(name = "USER_NAME")
    private String userName;


    @Column(nullable = false, name = "EMAIL")
    private String emailId;

    @Column(name = "MOBILE_NUMBER")
    private String mobileNumber;

    @Column(nullable = false, name = "PASSWORD")
    private String password;
}
