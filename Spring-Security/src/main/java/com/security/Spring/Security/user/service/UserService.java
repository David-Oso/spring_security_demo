package com.security.Spring.Security.user.service;


import com.security.Spring.Security.appUser.dto.request.ChangePasswordRequest;
import com.security.Spring.Security.appUser.dto.response.ChangePasswordResponse;
import com.security.Spring.Security.user.dto.request.LoginRequest;
import com.security.Spring.Security.user.dto.request.RegisterRequest;
import com.security.Spring.Security.user.dto.response.LoginResponse;
import com.security.Spring.Security.user.dto.response.RegisterResponse;

import java.security.Principal;

public interface UserService {
    RegisterResponse registerUser(RegisterRequest registerRequest);
    LoginResponse login(LoginRequest loginRequest);
    ChangePasswordResponse changePassword(ChangePasswordRequest changePasswordRequest, Principal user);
}
