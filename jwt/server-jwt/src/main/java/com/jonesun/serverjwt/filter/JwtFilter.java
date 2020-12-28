package com.jonesun.serverjwt.filter;

import com.jonesun.serverjwt.JWTUtils;
import com.nimbusds.jwt.JWTClaimsSet;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.AuthorityUtils;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.web.filter.GenericFilterBean;

import javax.servlet.FilterChain;
import javax.servlet.ServletException;
import javax.servlet.ServletRequest;
import javax.servlet.ServletResponse;
import javax.servlet.http.HttpServletRequest;
import java.io.IOException;
import java.util.List;
import java.util.stream.Collectors;

/**
 * 校验 token 的过滤器
 * 当其他请求发送来，如果校验成功，就让请求继续执行
 *
 * @author jone.sun
 * @date 2020-12-25 11:06
 */
public class JwtFilter extends GenericFilterBean {

    private final Logger logger = LoggerFactory.getLogger(this.getClass());

    @Override
    public void doFilter(ServletRequest servletRequest, ServletResponse servletResponse, FilterChain filterChain) throws IOException, ServletException {
        HttpServletRequest req = (HttpServletRequest) servletRequest;
        // 获取 token ，注意获取方式要跟前台传的方式保持一致
        // 这里请求时注意认证方式选择 Bearer Token，会用 header 传递
        String jwtToken = req.getHeader("authorization");
        if (jwtToken == null) {
            filterChain.doFilter(servletRequest, servletResponse);
            return;
        }

        //todo 校验后需做一些逻辑上的判断: 如是否为空、是否有效等
        JWTClaimsSet jwtClaimsSet = JWTUtils.verifyToken(jwtToken.replace("Bearer ", ""));
        // 获取用户名
        String username = jwtClaimsSet.getSubject();
        logger.info("username: " + username);

        // 获取用户角色，注意 "authorities" 要与生成 token 时的保持一致
        List<GrantedAuthority> authorities = jwtClaimsSet.getAudience().stream().map(SimpleGrantedAuthority::new).collect(Collectors.toList());
        UsernamePasswordAuthenticationToken token = new UsernamePasswordAuthenticationToken(username, null, authorities);
        SecurityContextHolder.getContext().setAuthentication(token);
        filterChain.doFilter(servletRequest, servletResponse);
    }

}