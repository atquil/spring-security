package com.atquil.springSecurity.dto;

import lombok.Data;
import lombok.NoArgsConstructor;

/**
 * @author atquil
 */

public record UserRegistrationDto (String userName, String userEmail, String userMobileNo, String userPassword){}
