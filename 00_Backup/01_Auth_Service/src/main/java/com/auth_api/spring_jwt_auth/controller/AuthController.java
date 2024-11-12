package com.auth_api.spring_jwt_auth.controller;

import com.auth_api.spring_jwt_auth.entity.User;
import com.auth_api.spring_jwt_auth.service.AuthService;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

@RestController
@RequestMapping("/api/v1/auth")
public class AuthController {

    private final AuthService authService;

    @Autowired
    public AuthController(AuthService  authService){
        this.authService=authService;
    }

    @PostMapping("/login")
    public ResponseEntity<String> userLogin(@RequestBody User user){
        return ResponseEntity.ok(authService.verifyUser(user));
    }

    @PostMapping("/register")
    public ResponseEntity<User> userRegistration(@RequestBody User user){
        return ResponseEntity.ok(authService.newUserRegistration(user));
    }
}
