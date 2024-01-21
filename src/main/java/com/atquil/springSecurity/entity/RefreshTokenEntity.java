package com.atquil.springSecurity.entity;

import jakarta.persistence.*;
import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;
import lombok.NoArgsConstructor;

/**
 * @author atquil
 */
@Entity
@Data
@Builder
@NoArgsConstructor
@AllArgsConstructor
@Table(name="REFRESH_TOKENS")
public class RefreshTokenEntity {

    @Id
    @GeneratedValue
    private Long id;
    // Increase the length to a value that can accommodate your actual token lengths
    @Column(name = "REFRESH_TOKEN", nullable = false, length = 10000)
    private String refreshToken;

    @Column(name = "REVOKED")
    private boolean revoked;

    @ManyToOne
    @JoinColumn(name = "user_id",referencedColumnName = "id")
    private UserInfoEntity user;

}
