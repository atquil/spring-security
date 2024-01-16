package com.atquil.springSecurity.service;

import com.atquil.springSecurity.config.jwtAuth.JwtTokenGenerator;
import com.atquil.springSecurity.dto.AuthResponseDto;
import com.atquil.springSecurity.enums.TokenType;
import com.atquil.springSecurity.repo.UserInfoRepo;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.http.HttpStatus;
import org.springframework.security.core.Authentication;
import org.springframework.stereotype.Service;
import org.springframework.web.server.ResponseStatusException;

/**
 * @author atquil
 */

@Service
@RequiredArgsConstructor
@Slf4j
public class AuthService {

    private final UserInfoRepo userInfoRepo;
    private final JwtTokenGenerator jwtTokenGenerator;
    public AuthResponseDto getJwtTokensAfterAuthentication(Authentication authentication) {
        try
        {
            //Return 500, as error to avoid guessing by malicious actors.

            var userDetailsEntity = userInfoRepo.findByEmailId(authentication.getName())
                    .orElseThrow(()->{
                        log.error("[AuthService:userSignInAuth] User :{} not found",authentication.getName());
                        return new ResponseStatusException(HttpStatus.INTERNAL_SERVER_ERROR,"Please Try Again ");});


            String accessToken = jwtTokenGenerator.generateAccessToken(authentication);

            log.info("[AuthService:userSignInAuth] Access token for user:{}, has been generated",userDetailsEntity.getUserName());
            return  AuthResponseDto.builder()
                    .accessToken(accessToken)
                    .accessTokenExpiry("60")
                    .userName(userDetailsEntity.getUserName())
                    .tokenType(TokenType.Bearer)
                    .build();


        }catch (Exception e){
            log.error("[AuthService:userSignInAuth]Exception while authenticating the user due to :"+e.getMessage());
            throw new ResponseStatusException(HttpStatus.INTERNAL_SERVER_ERROR,"Please Try Again");
        }
    }
}
