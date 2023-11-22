package com.security.Spring.Security.user.service;

import com.security.Spring.Security.appUser.dto.request.ChangePasswordRequest;
import com.security.Spring.Security.appUser.dto.response.ChangePasswordResponse;
import com.security.Spring.Security.user.dto.request.LoginRequest;
import com.security.Spring.Security.user.dto.request.RegisterRequest;
import com.security.Spring.Security.user.dto.response.LoginResponse;
import com.security.Spring.Security.user.dto.response.RegisterResponse;
import com.security.Spring.Security.user.model.Gender;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;

import static org.assertj.core.api.Assertions.assertThat;
@SpringBootTest
class userServiceImplTest {
    @Autowired UserService userService;
    private RegisterRequest registerRequest;
    @BeforeEach
    void setUp() {
        registerRequest = new RegisterRequest();
        registerRequest.setFirstName("Temx");
        registerRequest.setLastName("Dave");
        registerRequest.setEmail("temx@gmail.com");
        registerRequest.setPassword("Password123#");
        registerRequest.setGender(Gender.MALE);
    }

    @Test
    void registerUserTest() {
        RegisterResponse response = userService.registerUser(registerRequest);
        assertThat(response.getMessage()).isEqualTo("User registered successfully");
    }

    @Test
    void loginTest() {
        LoginRequest loginRequest = new LoginRequest();
        loginRequest.setEmail("temx@gmail.com");
        loginRequest.setPassword("Password123#");
        LoginResponse loginResponse = userService.login(loginRequest);
        assertThat(loginResponse.getMessage()).isEqualTo("User authenticated successfully");
        assertThat(loginResponse.getJwtResponse()).isNotNull();
    }

//    @Test
//    void changePasswordTest() {
//        ChangePasswordRequest changePasswordRequest = new ChangePasswordRequest();
//        changePasswordRequest.setCurrentPassword("Password123#");
//        changePasswordRequest.setNewPassword("Password123$");
//        changePasswordRequest.setConfirmPassword("Password123");
//    }

}
