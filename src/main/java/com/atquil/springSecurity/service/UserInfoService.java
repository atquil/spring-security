package com.atquil.springSecurity.service;

import com.atquil.springSecurity.config.JWTConfig.TokenGenerator;
import com.atquil.springSecurity.dto.AuthenticationResponse;
import com.atquil.springSecurity.dto.UserRegistrationDto;
import com.atquil.springSecurity.entities.RefreshTokenEntity;
import com.atquil.springSecurity.entities.UserDetailsEntity;
import com.atquil.springSecurity.mapper.UserDetailsMapper;
import com.atquil.springSecurity.repo.RefreshTokenRepo;
import com.atquil.springSecurity.repo.UserDetailsRepo;
import jakarta.servlet.http.Cookie;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.http.HttpStatus;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.stereotype.Service;
import org.springframework.web.server.ResponseStatusException;

import java.util.Arrays;
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
    private final RefreshTokenRepo refreshTokenRepo;

    public Object registerUser(UserRegistrationDto userRegistrationDto){

        try{
            log.info("User Registration Started with :::{}",userRegistrationDto);

            Optional<UserDetailsEntity> user = userDetailsRepo.findByEmailId(userRegistrationDto.userEmail());
            if(user.isPresent()){
                throw new Exception("User Already Exist");
            }

            UserDetailsEntity userDetailsEntity = userDetailsMapper.convertToEntity(userRegistrationDto);
            Authentication authentication = createAuthentication(userDetailsEntity);


            // Generate a JWT token
            String accessToken = tokenGenerator.generateAccessToken(authentication);
            String refreshToken = tokenGenerator.generateRefreshToken(authentication);

            UserDetailsEntity savedUserDetails = userDetailsRepo.save(userDetailsEntity);


            saveUserRefreshToken(userDetailsEntity,refreshToken);
            log.info(savedUserDetails.getUserName()+" account has been created");
            return  AuthenticationResponse.builder()
                    .accessToken(accessToken)
                    .refreshToken(refreshToken)
                    .build();


        }catch (Exception e){
            log.error("Exception while registering the user due to :"+e.getMessage());
            throw new ResponseStatusException(HttpStatus.BAD_REQUEST,e.getMessage());
        }

    }

    private void saveUserRefreshToken(UserDetailsEntity userDetailsEntity, String refreshToken) {
        //Save the refreshToken : to get new accessToken
        var refreshTokenEntity = RefreshTokenEntity.builder()
                .user(userDetailsEntity)
                .refreshToken(refreshToken)
                .expired(false)
                .revoked(false)
                .build();
        refreshTokenRepo.save(refreshTokenEntity);
    }

    private static Authentication createAuthentication(UserDetailsEntity userDetailsEntity) {
        // Extract user details from UserDetailsEntity
        String username = userDetailsEntity.getEmailId();
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


    public String getAllUserDetails() {
        System.out.println("Here with getALL users");
        try{
            return "userDetailsRepo.findAllUserDetailsEntity()";
        }catch (Exception e){
            throw new ResponseStatusException(HttpStatus.INTERNAL_SERVER_ERROR,e.getMessage());
        }

    }



    public AuthenticationResponse authenticateUser(Authentication authentication) {
        try
        {
            log.info(" Authenticating user :::"+authentication.getName());

            var userDetailsEntity = userDetailsRepo.findByEmailId(authentication.getName())
                    .orElseThrow(()->new ResponseStatusException(HttpStatus.BAD_REQUEST));


            String accessToken = tokenGenerator.generateAccessToken(authentication);
            String refreshToken = tokenGenerator.generateRefreshToken(authentication);

            //Before saving the refreshToken, let's revoke all the previous access
            revokeRefreshTokensForUser(userDetailsEntity.getEmailId());

            saveUserRefreshToken(userDetailsEntity,refreshToken);

            //Create HttpOnly Response:

            return  AuthenticationResponse.builder()
                    .accessToken(accessToken)
                    .refreshToken(refreshToken)
                    .build();


        }catch (Exception e){
            log.error("Exception while authenticating the user due to :"+e.getMessage());
            throw new ResponseStatusException(HttpStatus.BAD_REQUEST,e.getMessage());
        }
    }



    public Object deleteUser(String userEmail) {
        try{
            var userInfoEntity = userDetailsRepo.findByEmailId(userEmail)
                    .orElseThrow();
            userDetailsRepo.deleteById(userInfoEntity.getId());
            return "User:"+userInfoEntity.getUserName()+" has been deleted";
        }catch (Exception e){
            throw new ResponseStatusException(HttpStatus.BAD_REQUEST,e.getMessage());
        }

    }
    public String getAccessTokenUsingRefreshToken(String authorizationHeader) {

        // Extract the JWT token from the Authorization header
        String token = extractJwtToken(authorizationHeader);

        System.out.println("---refreshToken"+token);
        var refreshTokenEntity = refreshTokenRepo.findByRefreshToken(token)
                .filter(tokens-> !tokens.isExpired())
                .orElseThrow(()-> new ResponseStatusException(HttpStatus.BAD_REQUEST));

        UserDetailsEntity userDetailsEntity = refreshTokenEntity.getUser();
        Authentication authentication =  createAuthentication(userDetailsEntity);

        log.info("A new access token has been created for user:{}",userDetailsEntity.getUserName());

        return  tokenGenerator.generateAccessToken(authentication);
    }

    // Logout

    public Object revokeRefreshTokensForUser(String userEmail){

        log.info("Logging out the user:");
        var associatedRefreshTokenForUser = refreshTokenRepo.findByUserEmailId(userEmail);

        if(associatedRefreshTokenForUser.isEmpty()){
            return "Failure";
        }

        //All refreshToken has been inactive now.
        associatedRefreshTokenForUser.forEach(refreshToken -> {
            refreshToken.setExpired(true);
            refreshToken.setRevoked(true);
        });
        refreshTokenRepo.saveAll(associatedRefreshTokenForUser);
        //Revoke All refresh token
        return "SUCCESS";

    }

    private String extractJwtToken(String authorizationHeader) {
        // Assuming the header is in the format "Bearer <token>"
        if (authorizationHeader != null && authorizationHeader.startsWith("Bearer ")) {
            return authorizationHeader.substring(7);
        }
        return null;
    }


}
