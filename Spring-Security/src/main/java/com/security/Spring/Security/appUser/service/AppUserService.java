package com.security.Spring.Security.appUser.service;

import com.security.Spring.Security.appUser.dto.request.ChangePasswordRequest;
import com.security.Spring.Security.appUser.dto.response.ChangePasswordResponse;
import com.security.Spring.Security.appUser.dto.response.JwtResponse;
import com.security.Spring.Security.appUser.model.AppUser;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;

import java.io.IOException;
import java.security.Principal;

public interface AppUserService {
    ChangePasswordResponse changePassword(ChangePasswordRequest changePasswordRequest, Principal connectedUser);
    JwtResponse generateJwtToken(AppUser appUser);
    AppUser authenticate(String email, String password);
    void revokeAllUserTokens(AppUser appUser);
    void refreshToken(HttpServletRequest request, HttpServletResponse response) throws IOException;
}
