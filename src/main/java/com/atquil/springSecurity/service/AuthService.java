package com.atquil.springSecurity.service;

import com.atquil.springSecurity.config.jwtAuth.JwtTokenGenerator;
import com.atquil.springSecurity.dto.AuthResponseDto;
import com.atquil.springSecurity.entity.RefreshTokenEntity;
import com.atquil.springSecurity.entity.UserInfoEntity;
import com.atquil.springSecurity.enums.TokenType;
import com.atquil.springSecurity.repo.RefreshTokenRepo;
import com.atquil.springSecurity.repo.UserInfoRepo;
import jakarta.servlet.http.Cookie;
import jakarta.servlet.http.HttpServletResponse;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.http.HttpStatus;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.stereotype.Service;
import org.springframework.web.server.ResponseStatusException;

import java.util.Arrays;

/**
 * @author atquil
 */

@Service
@RequiredArgsConstructor
@Slf4j
public class AuthService {

    private final UserInfoRepo userInfoRepo;
    private final JwtTokenGenerator jwtTokenGenerator;
    private final RefreshTokenRepo refreshTokenRepo;
    public AuthResponseDto getJwtTokensAfterAuthentication(Authentication authentication, HttpServletResponse response) {
        try
        {
            //Return 500, as error to avoid guessing by malicious actors.

            var userInfoEntity = userInfoRepo.findByEmailId(authentication.getName())
                    .orElseThrow(()->{
                        log.error("[AuthService:userSignInAuth] User :{} not found",authentication.getName());
                        return new ResponseStatusException(HttpStatus.INTERNAL_SERVER_ERROR,"Please Try Again ");});


            String accessToken = jwtTokenGenerator.generateAccessToken(authentication);
            String refreshToken = jwtTokenGenerator.generateRefreshToken(authentication);

            //Let's save the refreshToken as well
            saveUserRefreshToken(userInfoEntity,refreshToken);
            log.info("[AuthService:userSignInAuth] Access token for user:{}, has been generated",userInfoEntity.getUserName());

            creatRefreshTokenCookie(response,refreshToken);

            return  AuthResponseDto.builder()
                    .accessToken(accessToken)
                    .accessTokenExpiry(5 * 60)
                    .userName(userInfoEntity.getUserName())
                    .tokenType(TokenType.Bearer)
                    .build();


        }catch (Exception e){
            log.error("[AuthService:userSignInAuth]Exception while authenticating the user due to :"+e.getMessage());
            throw new ResponseStatusException(HttpStatus.INTERNAL_SERVER_ERROR,"Please Try Again");
        }
    }

    private void creatRefreshTokenCookie(HttpServletResponse response, String refreshToken) {
        Cookie refreshTokenCookie = new Cookie("refresh_token",refreshToken);
        refreshTokenCookie.setHttpOnly(true);
        refreshTokenCookie.setSecure(true);
        refreshTokenCookie.setMaxAge(15 * 24 * 60 * 60 ); // in seconds
        response.addCookie(refreshTokenCookie);
    }

    private void saveUserRefreshToken(UserInfoEntity userDetailsEntity, String refreshToken) {
        var refreshTokenEntity = RefreshTokenEntity.builder()
                .user(userDetailsEntity)
                .refreshToken(refreshToken)
                .revoked(false)
                .build();
        refreshTokenRepo.save(refreshTokenEntity);
    }

    public Object getAccessTokenUsingRefreshToken(String authorizationHeader) {

        if(!authorizationHeader.startsWith(TokenType.Bearer.name())){
            return new ResponseStatusException(HttpStatus.INTERNAL_SERVER_ERROR,"Please verify your token");
        }

        final String refreshToken = authorizationHeader.substring(7);

        var refreshTokenEntity = refreshTokenRepo.findByRefreshToken(refreshToken)
                .filter(tokens-> !tokens.isRevoked())
                .orElseThrow(()-> new ResponseStatusException(HttpStatus.INTERNAL_SERVER_ERROR,"Refresh token revoked"));

        UserInfoEntity userInfoEntity = refreshTokenEntity.getUser();
        Authentication authentication =  createAuthentication(userInfoEntity);

        String accessToken = jwtTokenGenerator.generateAccessToken(authentication);

        return  AuthResponseDto.builder()
                .accessToken(accessToken)
                .accessTokenExpiry(5 * 60)
                .userName(userInfoEntity.getUserName())
                .tokenType(TokenType.Bearer)
                .build();
    }

    private static Authentication createAuthentication(UserInfoEntity userInfoEntity) {
        // Extract user details from UserDetailsEntity
        String username = userInfoEntity.getEmailId();
        String password = userInfoEntity.getPassword();
        String roles = userInfoEntity.getRoles();

        // Extract authorities from roles (comma-separated)
        String[] roleArray = roles.split(",");
        GrantedAuthority[] authorities = Arrays.stream(roleArray)
                .map(role -> (GrantedAuthority) role::trim)
                .toArray(GrantedAuthority[]::new);

        return new UsernamePasswordAuthenticationToken(username, password, Arrays.asList(authorities));
    }
}
