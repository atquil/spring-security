package com.atquil.springSecurity.mapper;

import com.atquil.springSecurity.dto.UserRegistrationDto;
import com.atquil.springSecurity.entities.UserInfoEntity;
import org.springframework.stereotype.Component;

/**
 * @author atquil
 */

@Component
public class UserInfoMapper {



    public UserInfoEntity convertToEntity(UserRegistrationDto userRegistrationDto) {

        UserInfoEntity userInfoEntity = new UserInfoEntity();
        userInfoEntity.setUserName(userRegistrationDto.userName());
        userInfoEntity.setEmailId(userRegistrationDto.userEmail());
        userInfoEntity.setMobileNumber(userRegistrationDto.userMobileNo());
        return userInfoEntity;
    }
}
