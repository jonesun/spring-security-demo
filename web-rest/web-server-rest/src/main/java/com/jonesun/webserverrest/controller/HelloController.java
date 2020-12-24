package com.jonesun.webserverrest.controller;

import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

/**
 * @author jone.sun
 * @date 2020-12-24 10:31
 */
@RestController()
@RequestMapping(value = "/api")
public class HelloController {

    @GetMapping("/sayHello")
    public String sayHello() {
        return "hello world";
    }

}
