package com.atquil.springSecurity.mapper;

import com.atquil.springSecurity.dto.UserRegistrationDto;
import com.atquil.springSecurity.entities.UserDetailsEntity;
import lombok.RequiredArgsConstructor;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Component;

/**
 * @author atquil
 */

@Component
@RequiredArgsConstructor
public class UserDetailsMapper {


    private final PasswordEncoder passwordEncoder;
    public UserDetailsEntity convertToEntity(UserRegistrationDto userRegistrationDto) {
        UserDetailsEntity userDetailsEntity = new UserDetailsEntity();
        userDetailsEntity.setUserName(userRegistrationDto.userName());
        userDetailsEntity.setEmailId(userRegistrationDto.userEmail());
        userDetailsEntity.setMobileNumber(userRegistrationDto.userMobileNo());
        userDetailsEntity.setRoles(userRegistrationDto.userRole());
        userDetailsEntity.setPassword(passwordEncoder.encode(userRegistrationDto.userPassword()));
        return userDetailsEntity;
    }
}
