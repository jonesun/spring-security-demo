package com.jonesun.oauth2server;

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.test.web.servlet.MockMvc;
import org.springframework.test.web.servlet.ResultActions;
import org.springframework.test.web.servlet.setup.MockMvcBuilders;
import org.springframework.web.context.WebApplicationContext;

import static org.springframework.security.test.web.servlet.request.SecurityMockMvcRequestBuilders.*;

@SpringBootTest
class Oauth2ServerApplicationTests {

    MockMvc mockMvc;

    @BeforeEach
    void setup(WebApplicationContext wac) {
        this.mockMvc = MockMvcBuilders.webAppContextSetup(wac).build();
    }

    @Test
    void contextLoads() {
    }

    @Test
    public void getMessageWithMockUserCustomUsername() {
        try {
            ResultActions resultActions = mockMvc.perform(formLogin().user("admin").password("123456"));
            resultActions.andReturn().getResponse();
        } catch (Exception e) {
            e.printStackTrace();
        }
    }
}
