package com.jonesun.webserver.controller;

import org.springframework.stereotype.Controller;
import org.springframework.web.bind.annotation.GetMapping;

/**
 * @author jone.sun
 * @date 2020-12-23 16:08
 */
@Controller
public class LoginController {

    @GetMapping("/login")
    String login() {
        return "login";
    }
}
