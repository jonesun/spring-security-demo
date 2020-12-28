package com.jonesun.multiplehttpsecurityserver.config;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.jonesun.multiplehttpsecurityserver.filter.JwtFilter;
import com.jonesun.multiplehttpsecurityserver.filter.JwtLoginFilter;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.core.annotation.Order;
import org.springframework.http.MediaType;
import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.security.authentication.DisabledException;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.security.crypto.password.NoOpPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.provisioning.InMemoryUserDetailsManager;
import org.springframework.security.provisioning.JdbcUserDetailsManager;
import org.springframework.security.web.WebAttributes;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;
import org.springframework.web.cors.CorsConfiguration;
import org.springframework.web.cors.UrlBasedCorsConfigurationSource;
import org.springframework.web.filter.CorsFilter;

import javax.servlet.RequestDispatcher;
import javax.servlet.http.HttpServletResponse;
import javax.sql.DataSource;
import java.io.PrintWriter;
import java.nio.charset.StandardCharsets;
import java.util.Collections;
import java.util.HashMap;
import java.util.Map;

/**
 * @author jone.sun
 * @date 2020-12-28 15:09
 */
@Configuration
public class MultiHttpSecurityConfig {

    @Bean
    public PasswordEncoder passwordEncoder() {
        // todo 设置默认的加密方式 此处仅为演示用，实际项目请改为其他加密方式如BCryptPasswordEncoder采用了SHA-256 +随机盐+密钥对密码进行加密，更加安全
        return NoOpPasswordEncoder.getInstance();
    }


    @Autowired
    DataSource dataSource;

    @Bean
    public UserDetailsService userDetailsService() throws Exception {
//        // ensure the passwords are encoded properly
//        User.UserBuilder users = User.withDefaultPasswordEncoder();
//        InMemoryUserDetailsManager manager = new InMemoryUserDetailsManager();
//        manager.createUser(users.username("user").password("111111").roles("USER").build());
//        manager.createUser(users.username("admin").password("123456").roles("USER", "ADMIN").build());

        JdbcUserDetailsManager manager = new JdbcUserDetailsManager();
        manager.setDataSource(dataSource);
        //todo 为测试方便手动加入两个用户 实际项目根据自己需要改为注册方式
        if (!manager.userExists("admin")) {
            manager.createUser(User.withUsername("admin").password("123456").roles("USER", "ADMIN").build());
        }
        if (!manager.userExists("user")) {
            manager.createUser(User.withUsername("user").password("111111").roles("USER").build());
        }
        return manager;
    }

    @Configuration
    @Order(1)
    public static class JwtApiWebSecurityConfigurationAdapter extends WebSecurityConfigurerAdapter {

        @Autowired
        private ObjectMapper objectMapper;

        @Override
        protected void configure(HttpSecurity http) throws Exception {
            http.
                    antMatcher("/app/**")
                    .authorizeRequests(authorize -> authorize
                            .anyRequest().hasRole("USER")
                    )
                    .addFilterBefore(new JwtLoginFilter("/app/login", authenticationManager()), UsernamePasswordAuthenticationFilter.class)
                    .addFilterBefore(new JwtFilter(), UsernamePasswordAuthenticationFilter.class)
                    .cors()
                    .and()
                    .csrf().disable()
                    .exceptionHandling()
                    //未登录
                    .authenticationEntryPoint((req, resp, authException) -> {
                        resp.setContentType(MediaType.APPLICATION_JSON_VALUE);
                        resp.setCharacterEncoding(StandardCharsets.UTF_8.toString());
                        resp.setStatus(HttpServletResponse.SC_FORBIDDEN);
                        PrintWriter out = resp.getWriter();
                        Map<String, Object> map = new HashMap<>();
                        map.put("code", HttpServletResponse.SC_FORBIDDEN);
                        map.put("message", "未登录-token为空");
                        out.write(objectMapper.writeValueAsString(map));
                        out.flush();
                        out.close();
                    })
                    //权限不足
                    .accessDeniedHandler((request, httpServletResponse, ex) -> {
                        ex.printStackTrace();
                        httpServletResponse.setStatus(HttpServletResponse.SC_OK);
                        httpServletResponse.setContentType(MediaType.APPLICATION_JSON_VALUE);
                        httpServletResponse.setCharacterEncoding(StandardCharsets.UTF_8.toString());
//                    httpServletResponse.setStatus(HttpServletResponse.SC_FORBIDDEN);
                        PrintWriter out = httpServletResponse.getWriter();
                        Map<String, Object> map = new HashMap<>();
                        map.put("code", HttpServletResponse.SC_FORBIDDEN);
                        map.put("message", "权限不足");
                        out.write(objectMapper.writeValueAsString(map));
                        out.flush();
                        out.close();
                    });
        }

    }

    @Configuration
    @Order(2)
    public static class ApiWebSecurityConfigurationAdapter extends WebSecurityConfigurerAdapter {

        @Autowired
        private ObjectMapper objectMapper;

        protected void configure(HttpSecurity http) throws Exception {

            http.antMatcher("/fore-web/**")
                    .authorizeRequests(authorize -> authorize
                            .anyRequest().hasRole("USER")
                    )
                    .cors()
                    .and()
                    .csrf().disable()
                    .formLogin()
                    .loginProcessingUrl("/fore-web/login")
                    .successHandler((httpServletRequest, httpServletResponse, authentication) -> {
                        System.out.println("登录成功: " + httpServletRequest.getSession().getId());
                        Map<String, Object> map = new HashMap<>();
                        map.put("code", 200);
                        map.put("message", "登录成功");
                        map.put("data", authentication);
                        httpServletResponse.setContentType(MediaType.APPLICATION_JSON_VALUE);
                        httpServletResponse.setCharacterEncoding(StandardCharsets.UTF_8.toString());
                        PrintWriter out = httpServletResponse.getWriter();
                        out.write(objectMapper.writeValueAsString(map));
                        out.flush();
                        out.close();
                    })
                    .failureHandler((req, resp, ex) -> {
//                    ex.printStackTrace();
                        resp.setContentType(MediaType.APPLICATION_JSON_VALUE);
                        resp.setCharacterEncoding(StandardCharsets.UTF_8.toString());
                        resp.setStatus(HttpServletResponse.SC_UNAUTHORIZED);
                        PrintWriter out = resp.getWriter();
                        Map<String, Object> map = new HashMap<>();
                        map.put("code", HttpServletResponse.SC_UNAUTHORIZED);
                        if (ex instanceof UsernameNotFoundException || ex instanceof BadCredentialsException) {
                            map.put("message", "用户名或密码错误");
                        } else if (ex instanceof DisabledException) {
                            map.put("message", "账户被禁用");
                        } else {
                            map.put("message", "登录失败!");
                        }
                        out.write(objectMapper.writeValueAsString(map));
                        out.flush();
                        out.close();
                    })
                    .permitAll()
                    .and()
                    .logout()
                    .logoutSuccessHandler((req, resp, authentication) -> {
                        Map<String, Object> map = new HashMap<String, Object>();
                        map.put("code", 200);
                        map.put("message", "退出成功");
                        map.put("data", authentication);
                        resp.setContentType(MediaType.APPLICATION_JSON_VALUE);
                        resp.setCharacterEncoding(StandardCharsets.UTF_8.toString());
                        PrintWriter out = resp.getWriter();
                        out.write(objectMapper.writeValueAsString(map));
                        out.flush();
                        out.close();
                    })
                    .permitAll()
                    .and()
                    .exceptionHandling()
                    //未登录
                    .authenticationEntryPoint((req, resp, authException) -> {
                        resp.setContentType(MediaType.APPLICATION_JSON_VALUE);
                        resp.setCharacterEncoding(StandardCharsets.UTF_8.toString());
                        resp.setStatus(HttpServletResponse.SC_FORBIDDEN);
                        PrintWriter out = resp.getWriter();
                        Map<String, Object> map = new HashMap<>();
                        map.put("code", HttpServletResponse.SC_FORBIDDEN);
                        map.put("message", "未登录");
                        out.write(objectMapper.writeValueAsString(map));
                        out.flush();
                        out.close();
                    })
                    //权限不足
                    .accessDeniedHandler((request, httpServletResponse, ex) -> {
                        httpServletResponse.setStatus(HttpServletResponse.SC_OK);
                        httpServletResponse.setContentType(MediaType.APPLICATION_JSON_VALUE);
                        httpServletResponse.setCharacterEncoding(StandardCharsets.UTF_8.toString());
//                    httpServletResponse.setStatus(HttpServletResponse.SC_FORBIDDEN);
                        PrintWriter out = httpServletResponse.getWriter();
                        Map<String, Object> map = new HashMap<>();
                        map.put("code", HttpServletResponse.SC_FORBIDDEN);
                        map.put("message", "权限不足");
                        out.write(objectMapper.writeValueAsString(map));
                        out.flush();
                        out.close();
                    })
            ;
        }
    }

    @Configuration
    public static class FormLoginWebSecurityConfigurerAdapter extends WebSecurityConfigurerAdapter {

        @Autowired
        private ObjectMapper objectMapper;

        @Override
        protected void configure(HttpSecurity http) throws Exception {
            http
//                    .authorizeRequests(authorize -> authorize
//                            .anyRequest().authenticated()
//                    )
                    .authorizeRequests(authorize -> authorize
                            .anyRequest().hasRole("ADMIN")
                    )
                    .formLogin()
                    .loginPage("/login")
                    .permitAll()
                    .and() //权限不足
                    .exceptionHandling()
                    .accessDeniedHandler((request, httpServletResponse, ex) -> {
                        request.setAttribute(WebAttributes.ACCESS_DENIED_403, ex);
                        httpServletResponse.setStatus(HttpServletResponse.SC_FORBIDDEN);
                        RequestDispatcher dispatcher = request.getRequestDispatcher("forbidden");
                        dispatcher.forward(request, httpServletResponse);
                    });

//                    .formLogin(withDefaults());
        }
    }

    @Bean
    public CorsFilter corsFilter() {
        CorsConfiguration corsConfiguration = new CorsConfiguration();
        //1,允许任何来源 *表示任何请求都视为同源(生产环境尽量在配置文件中动态配置部署到的域名)，若需指定ip和端口可以改为如“localhost：8080”
        corsConfiguration.setAllowedOriginPatterns(Collections.singletonList("*"));
        //2,允许任何请求头
        corsConfiguration.addAllowedHeader(CorsConfiguration.ALL);
        //3,允许任何方法
        corsConfiguration.addAllowedMethod(CorsConfiguration.ALL);
        //4,允许凭证
        corsConfiguration.setAllowCredentials(true);

        UrlBasedCorsConfigurationSource source = new UrlBasedCorsConfigurationSource();
        source.registerCorsConfiguration("/**", corsConfiguration);
        return new CorsFilter(source);
    }

}
