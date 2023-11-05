package com.atquil.springSecurity.controller;

import com.atquil.springSecurity.config.SecurityConfig;
import com.atquil.springSecurity.service.JWTTokenService;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.autoconfigure.web.servlet.WebMvcTest;
import org.springframework.context.annotation.Import;
import org.springframework.security.test.context.support.WithMockUser;
import org.springframework.test.web.servlet.MockMvc;
import org.springframework.test.web.servlet.MvcResult;

import static org.junit.jupiter.api.Assertions.*;
import static org.springframework.security.test.web.servlet.request.SecurityMockMvcRequestPostProcessors.httpBasic;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.content;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

/**
 * @author atquil
 */

//Slice test
@WebMvcTest({APIController.class, AuthController.class})
@Import({SecurityConfig.class, JWTTokenService.class})
class AuthControllerTest {


        @Autowired
        MockMvc mvc;
        @Test
        void rootWhenUnauthenticatedThen401() throws Exception {
            this.mvc.perform(get("/"))
                    .andExpect(status().isUnauthorized());
        }
        @Test
        void rootWhenAuthenticatedThenSaysHelloUser() throws Exception {
            MvcResult result = this.mvc.perform(post("/token")
                            .with(httpBasic("atquil", "password")))
                    .andExpect(status().isOk())
                    .andReturn();
            String token = result.getResponse().getContentAsString();
            this.mvc.perform(get("/api/dummy/user-detail")
                            .header("Authorization", "Bearer " + token))
                    .andExpect(content().string("atquil Is the user"));
        }
        @Test
        @WithMockUser
        public void rootWithMockUserStatusIsOK() throws Exception {
            this.mvc.perform(get("/api/dummy/user-detail")).andExpect(status().isOk());
        }
    }