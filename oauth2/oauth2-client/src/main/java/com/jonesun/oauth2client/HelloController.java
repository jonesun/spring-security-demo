package com.jonesun.oauth2client;

import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RestController;

/**
 * @author jone.sun
 * @date 2020-12-29 17:20
 */
@RestController
public class HelloController {

    @GetMapping
    public String sayHello() {
        return "hello world";
    }

}
