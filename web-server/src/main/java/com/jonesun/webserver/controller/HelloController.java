package com.jonesun.webserver.controller;

import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RestController;

/**
 * @author jone.sun
 * @date 2020-12-23 15:29
 */
@RestController
public class HelloController {

    @GetMapping("/")
    public String sayHello() {
        return "hello world";
    }

}
