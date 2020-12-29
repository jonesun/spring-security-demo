package com.jonesun.multiplehttpsecurityserver.dao;

import com.jonesun.multiplehttpsecurityserver.model.UserDO;

/**
 * @author jone.sun
 * @date 2020-12-29 13:21
 */
public interface UserDao {

    UserDO getByUsername(String username);
}
