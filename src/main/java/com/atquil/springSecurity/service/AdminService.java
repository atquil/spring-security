package com.atquil.springSecurity.service;

import com.atquil.springSecurity.repo.RefreshTokenRepo;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.stereotype.Service;

/**
 * @author atquil
 */
@Service
@RequiredArgsConstructor
@Slf4j
public class AdminService {
    private final RefreshTokenRepo refreshTokenRepo;

    public String revokeRefreshTokensForUser(String userEmail){

        var associatedRefreshTokenForUser = refreshTokenRepo.findAllRefreshTokenByUserEmailId(userEmail);

        if(associatedRefreshTokenForUser.isEmpty()){
            return "Failure";
        }
        //All refreshToken has been inactive now.
        associatedRefreshTokenForUser.forEach(refreshToken -> {

            refreshToken.setRevoked(true);
        });
        refreshTokenRepo.saveAll(associatedRefreshTokenForUser);
        //Revoke All refresh token
        return "SUCCESS";

    }

}
