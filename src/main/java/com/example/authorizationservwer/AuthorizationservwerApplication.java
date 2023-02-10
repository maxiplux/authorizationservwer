package com.example.authorizationservwer;

import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.context.annotation.ComponentScan;

@SpringBootApplication
@ComponentScan({"com.example.authorizationservwer"})
public class AuthorizationservwerApplication {

    public static void main(String[] args) {
        SpringApplication.run(AuthorizationservwerApplication.class, args);
    }

}
