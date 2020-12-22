package com.jonesun.oauth2resource;

import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RestController;

@RestController("/api")
public class HelloController {

    @PostMapping("/api/hi")
    public String say(String name) {
        return "hi , " + name;
    }

}