package com.security.Spring.Security.user.dto.response;

import com.security.Spring.Security.appUser.dto.response.JwtResponse;
import lombok.Builder;
import lombok.Getter;

@Builder
@Getter
public class LoginResponse {
    private String message;
    private JwtResponse jwtResponse;
}
