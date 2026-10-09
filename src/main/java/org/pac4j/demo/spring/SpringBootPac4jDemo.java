package org.pac4j.demo.spring;

import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;

// no more MongoDB auto-configuration to exclude: in Spring Boot 4, it lives in the spring-boot-mongodb module which is not a dependency
@SpringBootApplication
public class SpringBootPac4jDemo {

    public static void main(final String[] args) {
        SpringApplication.run(SpringBootPac4jDemo.class, args);
    }
}
