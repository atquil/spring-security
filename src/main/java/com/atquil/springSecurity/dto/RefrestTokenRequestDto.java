package com.atquil.springSecurity.dto;

import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;
import lombok.NoArgsConstructor;

/**
 * @author atquil
 */

@Data
@Builder
@NoArgsConstructor
@AllArgsConstructor
public class RefrestTokenRequestDto {
    private String refreshToken;
}
