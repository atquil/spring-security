package com.atquil.springSecurity.dto;

import com.atquil.springSecurity.enums.UserRole;

/**
 * @author atquil
 */

public record UserRegistrationDto (String userName,
                                   String userEmail,
                                   String userMobileNo,
                                   String userPassword,
                                   String userRole){}
