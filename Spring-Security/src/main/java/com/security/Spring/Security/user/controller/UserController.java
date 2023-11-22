package com.security.Spring.Security.user.controller;

import com.security.Spring.Security.appUser.dto.request.ChangePasswordRequest;
import com.security.Spring.Security.appUser.dto.response.ChangePasswordResponse;
import com.security.Spring.Security.user.dto.request.LoginRequest;
import com.security.Spring.Security.user.dto.request.RegisterRequest;
import com.security.Spring.Security.user.dto.response.LoginResponse;
import com.security.Spring.Security.user.dto.response.RegisterResponse;
import com.security.Spring.Security.user.service.UserService;
import jakarta.validation.Valid;
import lombok.RequiredArgsConstructor;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import java.security.Principal;

@RestController
@RequestMapping("/user/")
@RequiredArgsConstructor
public class UserController {
    private final UserService userService;

    @PostMapping("register")
    public ResponseEntity<?> register(@Valid @RequestBody RegisterRequest registerRequest){
        RegisterResponse response = userService.registerUser(registerRequest);
        return ResponseEntity.status(HttpStatus.CREATED).body(response);
    }

    @PostMapping("login")
    public ResponseEntity<?> login(@Valid @RequestBody LoginRequest loginRequest){
        LoginResponse loginResponse = userService.login(loginRequest);
        return ResponseEntity.ok(loginResponse);
    }

    @PostMapping("change_password")
    public ResponseEntity<?> changePassword(@Valid @RequestBody ChangePasswordRequest changePasswordRequest, Principal principal){
        ChangePasswordResponse changePasswordResponse = userService.changePassword(changePasswordRequest, principal);
        return ResponseEntity.ok(changePasswordResponse);
    }

    @PostMapping("/logout")
    public ResponseEntity<?> logout(){
     return ResponseEntity.ok("Logout successfully");
    }
}
