package com.jonesun.multiplehttpsecurityserver.dao;

import com.jonesun.multiplehttpsecurityserver.model.AuthorityDO;

import java.util.List;

/**
 * @author jone.sun
 * @date 2020-12-29 14:33
 */
public interface AuthorityDao {

    List<AuthorityDO> listByUsername(String username);

}
