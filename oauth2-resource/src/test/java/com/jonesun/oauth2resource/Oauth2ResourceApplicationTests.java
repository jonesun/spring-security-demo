package com.jonesun.oauth2resource;

import org.junit.jupiter.api.Test;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.core.userdetails.UserDetails;

@SpringBootTest
class Oauth2ResourceApplicationTests {

    private final Logger logger = LoggerFactory.getLogger(this.getClass());

    @Test
    void contextLoads() {

        User.UserBuilder users = User.withDefaultPasswordEncoder();
        UserDetails user = users
                .username("user")
                .password("password")
                .roles("USER")
                .build();

        logger.info(user.getUsername() + " " + user.getPassword());

        UserDetails admin = users
                .username("admin")
                .password("password")
                .roles("USER","ADMIN")
                .build();

        logger.info(admin.getUsername() + " " + admin.getPassword());
    }

}
