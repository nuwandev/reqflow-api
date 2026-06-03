package com.nuwandev.reqflowapi;

import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.scheduling.annotation.EnableScheduling;

@SpringBootApplication
@EnableScheduling
public class ReqflowApiApplication {

    public static void main(String[] args) {
        SpringApplication.run(ReqflowApiApplication.class, args);
    }

}
