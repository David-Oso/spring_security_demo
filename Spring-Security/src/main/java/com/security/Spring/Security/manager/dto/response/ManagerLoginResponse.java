package com.security.Spring.Security.manager.dto.response;

import com.security.Spring.Security.appUser.dto.response.JwtResponse;
import lombok.Builder;
import lombok.Getter;

@Builder
@Getter
public class ManagerLoginResponse {
    private String message;
    private JwtResponse jwtResponse;
}
