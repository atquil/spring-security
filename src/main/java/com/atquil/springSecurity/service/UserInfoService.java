package com.atquil.springSecurity.service;

import com.atquil.springSecurity.dto.UserLoginUsingEmailDto;
import com.atquil.springSecurity.dto.UserRegistrationDto;
import com.atquil.springSecurity.entities.UserInfoEntity;
import com.atquil.springSecurity.mapper.UserInfoMapper;
import com.atquil.springSecurity.repo.UserInfoRepo;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.http.HttpStatus;
import org.springframework.stereotype.Service;
import org.springframework.web.server.ResponseStatusException;

import java.util.Optional;

/**
 * @author atquil
 */

@Service
@RequiredArgsConstructor
@Slf4j
public class UserInfoService {
    private final UserInfoRepo userInfoRepo;
    private final UserInfoMapper userInfoMapper;

    public String registerUser(UserRegistrationDto userRegistrationDto){

        log.info("UserRegistrationDto:::"+userRegistrationDto);
        Optional<UserInfoEntity> user = userInfoRepo.findByEmailId(userRegistrationDto.userEmail());
        if(user.isPresent()){
            throw new ResponseStatusException(HttpStatus.BAD_REQUEST, "User with emailId:"+userRegistrationDto.userEmail()+" already exist");
        }
        // Now Map the DTO to Entities
        UserInfoEntity userInfoEntity = userInfoMapper.convertToEntity(userRegistrationDto);
        //About password, we will have to encode it then save it.

        userInfoEntity.setPassword(userRegistrationDto.userPassword()); // Need to encrypt
        //Save the user

        UserInfoEntity savedUserDetails = userInfoRepo.save(userInfoEntity);
    return  savedUserDetails.getUserName()+" account has been created";
    }

    public String getUserDetailsUsingEmail(UserLoginUsingEmailDto userLoginUsingEmailDto) {
        Optional<UserInfoEntity> user = userInfoRepo.findByEmailId(userLoginUsingEmailDto.userEmail());
        if(user.isEmpty()){
            throw new ResponseStatusException(HttpStatus.NOT_FOUND, userLoginUsingEmailDto.userEmail()+ " not found. Please consider registering");
        }
        UserInfoEntity userInfoEntity = user.get();
        return userInfoEntity.getUserName();

    }
}
