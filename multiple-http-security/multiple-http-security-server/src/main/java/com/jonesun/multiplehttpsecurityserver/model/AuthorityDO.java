package com.jonesun.multiplehttpsecurityserver.model;

/**
 * @author jone.sun
 * @date 2020-12-29 14:07
 */
public class AuthorityDO {

    private String username;
    private String authority;

    public AuthorityDO(String authority) {
        this.authority = authority;
    }

    public String getUsername() {
        return username;
    }

    public void setUsername(String username) {
        this.username = username;
    }

    public String getAuthority() {
        return authority;
    }

    public void setAuthority(String authority) {
        this.authority = authority;
    }
}
