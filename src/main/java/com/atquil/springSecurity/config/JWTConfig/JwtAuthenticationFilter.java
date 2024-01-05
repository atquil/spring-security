package com.atquil.springSecurity.config.JWTConfig;

import com.atquil.springSecurity.service.UserInfoService;
import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import lombok.AllArgsConstructor;
import lombok.NoArgsConstructor;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Lazy;
import org.springframework.http.HttpHeaders;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.context.SecurityContext;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.oauth2.jwt.Jwt;
import org.springframework.security.oauth2.jwt.JwtDecoder;
import org.springframework.security.oauth2.jwt.JwtException;
import org.springframework.security.oauth2.jwt.NimbusJwtDecoder;
import org.springframework.security.web.authentication.WebAuthenticationDetailsSource;
import org.springframework.stereotype.Component;
import org.springframework.stereotype.Service;
import org.springframework.web.filter.OncePerRequestFilter;

import java.io.IOException;

/**
 * @author atquil
 */



@RequiredArgsConstructor
@Slf4j
public class JwtAuthenticationFilter extends OncePerRequestFilter {


    private  final RSAKeyRecord rsaKeyRecord;
    private final TokenUtils tokenUtils;

    @Override
    protected void doFilterInternal(HttpServletRequest request,
                                    HttpServletResponse response,
                                    FilterChain filterChain) throws ServletException, IOException {
        log.info("--------- Filtering the Http Request for:{}",request.getRequestURI());


        final String authHeader = request.getHeader(HttpHeaders.AUTHORIZATION);
        JwtDecoder jwtDecoder =  NimbusJwtDecoder.withPublicKey(rsaKeyRecord.rsaPublicKey()).build();
        // If the token is not Bearer, then we don't need to do any settings.
        if(!authHeader.startsWith("Bearer ")){
            filterChain.doFilter(request,response);
            return;
        }

        final String token = authHeader.substring(7);
        final Jwt jwtToken = jwtDecoder.decode(token);


        final String userName = tokenUtils.getUserName(jwtToken);



        //If not able to find the userName or if user has not authenticated
        if(!userName.isEmpty() && SecurityContextHolder.getContext().getAuthentication() == null){
            UserDetails userDetails = tokenUtils.userDetails(userName);

            if(tokenUtils.isTokenValid(jwtToken,userDetails)){
                SecurityContext securityContext = SecurityContextHolder.createEmptyContext();

                UsernamePasswordAuthenticationToken createdToken = new UsernamePasswordAuthenticationToken(
                        userDetails,
                        null,
                        userDetails.getAuthorities()
                );

                log.info("Role for user:{} is:{}",userName,createdToken.getAuthorities());
                createdToken.setDetails(new WebAuthenticationDetailsSource().buildDetails(request));

                securityContext.setAuthentication(createdToken);
                SecurityContextHolder.setContext(securityContext);
            }
        }

        filterChain.doFilter(request,response);
    }


}
