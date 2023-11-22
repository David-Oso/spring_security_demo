package com.security.Spring.Security.admin.dto.response;

import com.security.Spring.Security.appUser.dto.response.JwtResponse;
import lombok.Builder;
import lombok.Getter;

@Builder
@Getter
public class AdminLoginResponse {
    private String message;
    private JwtResponse jwtResponse;
}
