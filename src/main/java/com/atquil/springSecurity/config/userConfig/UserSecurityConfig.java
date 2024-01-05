package com.atquil.springSecurity.config.userConfig;

import com.atquil.springSecurity.entities.UserDetailsEntity;
import lombok.RequiredArgsConstructor;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.userdetails.UserDetails;

import java.util.Arrays;
import java.util.Collection;

/**
 * @author atquil
 */
@RequiredArgsConstructor
public class UserSecurityConfig  implements UserDetails {
    private  final UserDetailsEntity userDetailsEntity;

    @Override
    public Collection<? extends GrantedAuthority> getAuthorities() {
        return Arrays
                .stream(userDetailsEntity
                        .getRoles()
                        .split(","))
                .map(SimpleGrantedAuthority::new)
                .toList();
    }

    @Override
    public String getPassword() {
        return userDetailsEntity.getPassword();
    }

    @Override
    public String getUsername() {
        return userDetailsEntity.getEmailId();
    }

    @Override
    public boolean isAccountNonExpired() {
        return true;
    }

    @Override
    public boolean isAccountNonLocked() {
        return true;
    }

    @Override
    public boolean isCredentialsNonExpired() {
        return true;
    }

    @Override
    public boolean isEnabled() {
        return true;
    }
}
