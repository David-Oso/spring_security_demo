package com.security.Spring.Security.appUser.service;

import com.security.Spring.Security.appUser.dto.request.ChangePasswordRequest;
import com.security.Spring.Security.appUser.dto.response.ChangePasswordResponse;

import java.security.Principal;

public interface AppUserService {
    ChangePasswordResponse changePassword(ChangePasswordRequest changePasswordRequest, Principal connectedUser);
}
