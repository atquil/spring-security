package com.atquil.springSecurity.entities;

import jakarta.persistence.*;
import lombok.Data;

import java.time.Instant;

/**
 * @author atquil
 */

@Entity
@Data
@Table(name="TOKEN")
public class Token {

    @Id
    @GeneratedValue(strategy = GenerationType.AUTO)
    private long id;

    @OneToOne
    @JoinColumn(name = "user_id", referencedColumnName = "id")
    private UserDetailsEntity user;

    @Column(nullable = false, unique = true)
    private String accessToken;

    @Column(nullable = false)
    private Instant expiryDate;

}
