package com.atquil.springSecurity.dto;

import com.atquil.springSecurity.enums.TokenType;
import com.fasterxml.jackson.annotation.JsonProperty;
import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;
import lombok.NoArgsConstructor;

/**
 * @author atquil
 */
@Data
@Builder
@AllArgsConstructor
@NoArgsConstructor
public class AuthResponseDto {

    @JsonProperty("access_token")
    private String accessToken;

    @JsonProperty("access_token_expiry")
    private String accessTokenExpiry;

    @JsonProperty("token_type")
    private TokenType tokenType;

    @JsonProperty("user_name")
    private String userName;

}
