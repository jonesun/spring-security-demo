package com.jonesun.serverjwt.controller;

import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.ObjectMapper;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import java.util.HashMap;
import java.util.Map;

/**
 * @author jone.sun
 * @date 2020-12-24 10:31
 */
@RestController()
@RequestMapping(value = "/api")
public class HelloController {

    @Autowired
    private ObjectMapper objectMapper;

    @GetMapping("/sayHello")
    public String sayHello() throws JsonProcessingException {
        Map<String, Object> map = new HashMap<>();
        map.put("code", 200);
        map.put("message", "");
        map.put("data", "hello world");
        return objectMapper.writeValueAsString(map);
    }

}
