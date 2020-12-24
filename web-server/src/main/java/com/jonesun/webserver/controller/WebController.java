package com.jonesun.webserver.controller;

import org.springframework.security.authentication.AnonymousAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.stereotype.Controller;
import org.springframework.web.bind.annotation.GetMapping;

/**
 * 映射web页面
 * @author jone.sun
 * @date 2020-12-23 16:08
 */
@Controller
public class WebController {

    @GetMapping("/login")
    String login() {
        //当已登录用户再次访问登录界面时，跳转到index页面
        Authentication auth = SecurityContextHolder.getContext().getAuthentication();
        if(auth instanceof AnonymousAuthenticationToken){
            return "login";
        }else{
            return "redirect:index";
        }
    }

    @GetMapping("/index")
    String index() {
        return "index";
    }

    @GetMapping("/")
    String defaultIndex() {
        return index();
    }

    @GetMapping("/custom")
    String custom() {
        return "custom";
    }
}
