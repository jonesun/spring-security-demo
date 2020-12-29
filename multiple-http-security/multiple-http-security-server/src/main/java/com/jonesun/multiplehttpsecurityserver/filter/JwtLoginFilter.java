package com.jonesun.multiplehttpsecurityserver.filter;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.jonesun.multiplehttpsecurityserver.JWTUtils;
import com.jonesun.multiplehttpsecurityserver.model.LoginUser;
import org.springframework.http.MediaType;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.AuthenticationServiceException;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.web.authentication.AbstractAuthenticationProcessingFilter;
import org.springframework.security.web.util.matcher.AntPathRequestMatcher;

import javax.servlet.FilterChain;
import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;
import java.io.PrintWriter;
import java.util.HashMap;
import java.util.Map;

/**
 * 用户登录的过滤器
 * 在用户的登录的过滤器中校验用户是否登录成功
 * 如果登录成功，则生成一个 token 返回给客户端，登录失败则给前端一个登录失败的提示
 *
 * @author jone.sun
 * @date 2020-12-25 11:03
 */
public class JwtLoginFilter extends AbstractAuthenticationProcessingFilter {


    public JwtLoginFilter(String defaultFilterProcessesUrl, AuthenticationManager authenticationManager) {
        super(new AntPathRequestMatcher(defaultFilterProcessesUrl));
        setAuthenticationManager(authenticationManager);
    }

    @Override
    public Authentication attemptAuthentication(HttpServletRequest req, HttpServletResponse httpServletResponse) throws AuthenticationException, IOException {
        // 支持json与form表单登录方式
        String contentType = req.getContentType();
        if (req.getContentType().startsWith(MediaType.APPLICATION_FORM_URLENCODED_VALUE)) {
            String username = req.getParameter("username");
            String password = req.getParameter("password");
            //进行登录校验，如果校验成功，会到 successfulAuthentication 的回调中，否则到 unsuccessfulAuthentication 的回调中
            return getAuthenticationManager().authenticate(new UsernamePasswordAuthenticationToken(username, password));
        } else if (req.getContentType().startsWith(MediaType.APPLICATION_JSON_VALUE)) {
            LoginUser loginUser = new ObjectMapper().readValue(req.getInputStream(), LoginUser.class);
            return getAuthenticationManager().authenticate(new UsernamePasswordAuthenticationToken(loginUser.getUsername(), loginUser.getPassword()));
        } else {
            throw new AuthenticationServiceException("contentType not supported: " + contentType);
        }
    }

    @Override
    protected void successfulAuthentication(HttpServletRequest request, HttpServletResponse resp, FilterChain chain, Authentication authentication) throws IOException, ServletException {
        String jwt = JWTUtils.buildToken(authentication);

        resp.setContentType("application/json;charset=utf-8");
        Map<String, String> map = new HashMap<>();
        map.put("token", jwt);
        map.put("msg", "登录成功");
        PrintWriter out = resp.getWriter();
        out.write(new ObjectMapper().writeValueAsString(map));
        out.flush();
        out.close();
    }

    @Override
    protected void unsuccessfulAuthentication(HttpServletRequest req, HttpServletResponse resp, AuthenticationException failed) throws IOException, ServletException {
        resp.setContentType("application/json;charset=utf-8");
        Map<String, String> map = new HashMap<>();
        map.put("msg", "登录失败");
        map.put("error", failed.getMessage());
        PrintWriter out = resp.getWriter();
        out.write(new ObjectMapper().writeValueAsString(map));
        out.flush();
        out.close();
    }
}