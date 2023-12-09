package com.atquil.springSecurity.config;

import com.atquil.springSecurity.entity.UserEntity;
import com.atquil.springSecurity.repo.UserRepo;
import lombok.RequiredArgsConstructor;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.stereotype.Service;

import java.util.Optional;

/**
 * @author atquil
 */
@Service
@RequiredArgsConstructor
public class JPAUserDetailsManagerConfig implements UserDetailsService {
//UserDetails simply store user info which is later encapsulated into Authentication object.

    private final UserRepo userRepo;
    @Override
    public UserDetails loadUserByUsername(String username) throws UsernameNotFoundException {
        Optional<UserEntity> user = userRepo.findByUsername(username);
        return userRepo
                .findByUsername(username)
                .map(UserSecurityConfig::new)
                .orElseThrow(()-> new UsernameNotFoundException("User :"+username+" does not exist"));
    }
}
