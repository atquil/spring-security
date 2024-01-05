package com.atquil.springSecurity.service;

import com.atquil.springSecurity.config.JWTConfig.TokenGenerator;
import com.atquil.springSecurity.config.userConfig.UserDetailsManagerConfig;
import com.atquil.springSecurity.dto.UserRegistrationDto;
import com.atquil.springSecurity.entities.UserDetailsEntity;
import com.atquil.springSecurity.mapper.UserDetailsMapper;
import com.atquil.springSecurity.repo.UserDetailsRepo;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.http.HttpStatus;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.stereotype.Service;
import org.springframework.web.server.ResponseStatusException;

import java.util.Arrays;
import java.util.List;
import java.util.Optional;

/**
 * @author atquil
 */

@Service
@RequiredArgsConstructor
@Slf4j
public class UserInfoService {
    private final UserDetailsRepo userDetailsRepo;
    private final UserDetailsMapper userDetailsMapper;
    private final TokenGenerator tokenGenerator;
  //  private final UserDetailsManagerConfig userDetailsManagerConfig;
    public String registerUser(UserRegistrationDto userRegistrationDto){

        try{
            log.info("User Registration Started with :::"+userRegistrationDto);

            Optional<UserDetailsEntity> user = userDetailsRepo.findByEmailId(userRegistrationDto.userEmail());
            if(user.isPresent()){
                throw new Exception("User Already Exist");
            }

            UserDetailsEntity userDetailsEntity = userDetailsMapper.convertToEntity(userRegistrationDto);
            Authentication authentication = createAuthentication(userDetailsEntity);

            // Generate a JWT token
            String jwtToken = tokenGenerator.generateAccessTOKEN(authentication);

            UserDetailsEntity savedUserDetails = userDetailsRepo.save(userDetailsEntity);

            log.info(savedUserDetails.getUserName()+" account has been created");
            return  jwtToken;


        }catch (Exception e){
            log.error("Exception while registering the user due to :"+e.getMessage());
            throw new ResponseStatusException(HttpStatus.BAD_REQUEST,e.getMessage());
        }
    }

    private static Authentication createAuthentication(UserDetailsEntity userDetailsEntity) {
        // Extract user details from UserDetailsEntity
        String username = userDetailsEntity.getUserName();
        String password = userDetailsEntity.getPassword();
        String roles = userDetailsEntity.getRoles();

        // Extract authorities from roles (comma-separated)
        String[] roleArray = roles.split(",");
        GrantedAuthority[] authorities = Arrays.stream(roleArray)
                .map(role -> (GrantedAuthority) role::trim)
                .toArray(GrantedAuthority[]::new);

        // Create Authentication object
        return new UsernamePasswordAuthenticationToken(username, password, Arrays.asList(authorities));
    }


    public List<UserDetailsEntity> getAllUserDetails() {
       return userDetailsRepo.findAll();
    }

    public String deleteUser(String userEmail) {
        Optional<UserDetailsEntity> userInfoEntity =  userDetailsRepo.findByEmailId(userEmail);
        if(userInfoEntity.isEmpty()){
            throw new ResponseStatusException(HttpStatus.NOT_FOUND);
        }

        userDetailsRepo.deleteById(userInfoEntity.get().getId());
        return "User:"+userInfoEntity.get().getUserName()+" has been deleted";
    }


}
