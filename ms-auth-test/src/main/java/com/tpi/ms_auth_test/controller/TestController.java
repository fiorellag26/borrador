package com.tpi.ms_auth_test.controller;

import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RestController;

@RestController
public class TestController {

    @GetMapping("/public")
    public String publicEndpoint() {
        return "Endpoint público OK";
    }

    @GetMapping("/secured")
    public String securedEndpoint() {
        return "Endpoint seguro OK – token válido";
    }

    @GetMapping("/admin-only")
    public String adminEndpoint() {
        return "Solo admins – rol validado correctamente";
    }
}
