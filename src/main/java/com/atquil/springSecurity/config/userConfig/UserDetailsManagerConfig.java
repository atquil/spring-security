package com.atquil.springSecurity.config.userConfig;

import com.atquil.springSecurity.repo.UserDetailsRepo;
import lombok.RequiredArgsConstructor;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.stereotype.Service;

/**
 * @author atquil
 */
@Service
@RequiredArgsConstructor
public class UserDetailsManagerConfig implements UserDetailsService {
    private final UserDetailsRepo userDetailsRepo;
    @Override
    public UserDetails loadUserByUsername(String emailId) throws UsernameNotFoundException {
        return userDetailsRepo
                .findByEmailId(emailId)
                .map(UserSecurityConfig::new)
                .orElseThrow(()-> new UsernameNotFoundException("UserEmail: "+emailId+" does not exist"));
    };

}
