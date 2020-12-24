package com.jonesun.webserverrest.config;

import com.fasterxml.jackson.databind.ObjectMapper;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.http.MediaType;
import org.springframework.security.authentication.AuthenticationProvider;
import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.security.authentication.DisabledException;
import org.springframework.security.authentication.dao.DaoAuthenticationProvider;
import org.springframework.security.config.annotation.authentication.builders.AuthenticationManagerBuilder;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.builders.WebSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.NoOpPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.web.authentication.AuthenticationSuccessHandler;
import org.springframework.security.web.csrf.CookieCsrfTokenRepository;
import org.springframework.web.cors.CorsConfiguration;
import org.springframework.web.cors.CorsConfigurationSource;
import org.springframework.web.cors.UrlBasedCorsConfigurationSource;
import org.springframework.web.filter.CorsFilter;
import org.springframework.web.servlet.config.annotation.CorsRegistry;
import org.springframework.web.servlet.config.annotation.WebMvcConfigurer;

import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;
import java.io.PrintWriter;
import java.util.Arrays;
import java.util.HashMap;
import java.util.Map;
import java.util.function.Function;

/**
 * @author jone.sun
 * @date 2020-12-23 15:44
 */
@Configuration
public class WebSecurityConfig extends WebSecurityConfigurerAdapter {

    @Autowired
    private ObjectMapper objectMapper;

    @Bean
    public UserDetailsService userDetailsService() {
        //获取用户账号密码及权限信息
        return username -> {
            System.out.println("username: " + username);
            return User.withUsername("admin").password("123456").passwordEncoder(s -> s).roles("USER").build();
        };
    }

    @Bean
    public PasswordEncoder passwordEncoder() {
        // 设置默认的加密方式（强hash方式加密）
        return NoOpPasswordEncoder.getInstance();
    }

    @Override
    public void configure(WebSecurity web) throws Exception {
        //如果登录页面引用了js、css等静态资源的话需要加入
        web.ignoring().antMatchers("/*.html","/js/**", "/css/**","/images/**");
    }

    @Override
    protected void configure(AuthenticationManagerBuilder auth) throws Exception {
        auth.userDetailsService(userDetailsService());
    }

    @Override
    protected void configure(HttpSecurity http) throws Exception {
//        super.configure(http);

        http.authorizeRequests()
                .anyRequest().authenticated()
                .and()
                .cors()
                .and()
                .csrf().disable()
                .formLogin()
                .successHandler((httpServletRequest, httpServletResponse, authentication) -> {

                    System.out.println("登录成功: " + httpServletRequest.getSession().getId());

                    Map<String, Object> map = new HashMap<>();
                    map.put("code", 200);
                    map.put("message", "登录成功");
                    map.put("data", authentication);
                    httpServletResponse.setContentType(MediaType.APPLICATION_JSON_UTF8_VALUE);
                    PrintWriter out = httpServletResponse.getWriter();
                    out.write(objectMapper.writeValueAsString(map));
                    out.flush();
                    out.close();
                })
                .failureHandler((req, resp, ex) -> {
//                    ex.printStackTrace();
                    resp.setContentType(MediaType.APPLICATION_JSON_UTF8_VALUE);
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
                    resp.setContentType(MediaType.APPLICATION_JSON_UTF8_VALUE);
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
                    resp.setContentType(MediaType.APPLICATION_JSON_UTF8_VALUE);
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
                .accessDeniedHandler((request, response, ex) -> {
                    response.setContentType(MediaType.APPLICATION_JSON_UTF8_VALUE);
                    response.setStatus(HttpServletResponse.SC_FORBIDDEN);
                    PrintWriter out = response.getWriter();
                    Map<String, Object> map = new HashMap<>();
                    map.put("code", HttpServletResponse.SC_FORBIDDEN);
                    map.put("message", "权限不足");
                    out.write(objectMapper.writeValueAsString(map));
                    out.flush();
                    out.close();
                })
        ;
    }

    @Bean
    CorsConfigurationSource corsConfigurationSource() {
        UrlBasedCorsConfigurationSource source =   new UrlBasedCorsConfigurationSource();
        CorsConfiguration corsConfiguration = new CorsConfiguration();
        corsConfiguration.addAllowedOrigin("*");    //同源配置，*表示任何请求都视为同源(生产环境尽量在配置文件中动态配置部署到的域名)，若需指定ip和端口可以改为如“localhost：8080”，多个以“，”分隔；
        corsConfiguration.addAllowedHeader("*");//header，允许哪些header
        corsConfiguration.addAllowedMethod("*");    //允许的请求方法，POST、GET等
        source.registerCorsConfiguration("/**",corsConfiguration); //配置允许跨域访问的url
        return source;
//        CorsConfiguration configuration = new CorsConfiguration();
//        //idea 运行静态网页的默认端口为63342
//        configuration.setAllowedOrigins(Arrays.asList("http://localhost:63342"));
//        configuration.setAllowedHeaders(Arrays.asList("Cookie"));
//        configuration.setAllowedMethods(Arrays.asList("GET", "POST", "PUT", "DELETE", "OPTIONS"));
//        configuration.setAllowCredentials(true);
//        UrlBasedCorsConfigurationSource source = new UrlBasedCorsConfigurationSource();
//        source.registerCorsConfiguration("/**", configuration);
//        return source;
    }

}
