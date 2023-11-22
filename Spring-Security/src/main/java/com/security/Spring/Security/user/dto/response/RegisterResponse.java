package com.security.Spring.Security.user.dto.response;


import lombok.Builder;
import lombok.Getter;

@Builder
@Getter
public class RegisterResponse {
    private String message;
    private boolean isEnabled;
}
