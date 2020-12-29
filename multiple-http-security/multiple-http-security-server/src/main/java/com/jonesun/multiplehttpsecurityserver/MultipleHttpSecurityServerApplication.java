package com.jonesun.multiplehttpsecurityserver;

import org.mybatis.spring.annotation.MapperScan;
import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;

@MapperScan(basePackages = {"com.jonesun.multiplehttpsecurityserver.dao"})
@SpringBootApplication
public class MultipleHttpSecurityServerApplication {

    public static void main(String[] args) {
        SpringApplication.run(MultipleHttpSecurityServerApplication.class, args);
    }

}
