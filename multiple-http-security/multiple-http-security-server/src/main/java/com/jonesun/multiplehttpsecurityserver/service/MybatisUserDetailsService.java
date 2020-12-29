package com.jonesun.multiplehttpsecurityserver.service;

import com.jonesun.multiplehttpsecurityserver.dao.AuthorityDao;
import com.jonesun.multiplehttpsecurityserver.dao.UserDao;
import com.jonesun.multiplehttpsecurityserver.model.AuthorityDO;
import com.jonesun.multiplehttpsecurityserver.model.UserDO;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.UsernameNotFoundException;

import java.util.*;
import java.util.stream.Collectors;


/**
 * @author jone.sun
 * @date 2020-12-28 18:13
 */
public class MybatisUserDetailsService implements UserDetailsService {

    private final Logger logger = LoggerFactory.getLogger(getClass());

    @Autowired
    private UserDao userDao;

    @Autowired
    private AuthorityDao authorityDao;

    @Override
    public UserDetails loadUserByUsername(String username) throws UsernameNotFoundException {
        UserDO userDO = userDao.getByUsername(username);
        if (userDO == null) {
            this.logger.error("用户: " + username + "不存在");
            throw new UsernameNotFoundException("用户: " + username + "不存在");
        }
        List<AuthorityDO> authorityDOList = authorityDao.listByUsername(username);
        if (authorityDOList == null || authorityDOList.size() == 0) {
            this.logger.error("用户:  " + username + " 无任何权限");
            throw new UsernameNotFoundException("用户:  " + username + " 无任何权限");
        }

        List<GrantedAuthority> authorities = authorityDOList.stream()
                .map(authorityDO -> new SimpleGrantedAuthority(authorityDO.getAuthority()))
                .collect(Collectors.toList());


        return new User(userDO.getUsername(), userDO.getPassword(), userDO.getEnabled(),
                true, true, true, authorities);
    }

}