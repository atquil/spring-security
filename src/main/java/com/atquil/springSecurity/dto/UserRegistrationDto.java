package com.atquil.springSecurity.dto;


import jakarta.validation.constraints.Email;
import jakarta.validation.constraints.NotEmpty;
import jakarta.validation.constraints.NotNull;
import org.springframework.lang.NonNull;

/**
 * @author atquil
 */

public record UserRegistrationDto (


        String userName,
        @NotNull(message = "User email must not be null")
        @NotEmpty(message = "User email must not be empty")
        @Email(message = "Invalid email format")
        String userEmail,
        String userMobileNo,
        @NotNull(message = "User password must not be null")
        @NotEmpty(message = "User password must not be empty")
        String userPassword,
        @NotNull(message = "User role must not be null")
        @NotEmpty(message = "User role must not be empty")
        String userRole){


}
