package com.security.Spring.Security.admin.service;

import com.security.Spring.Security.admin.dto.request.AdminLoginRequest;
import com.security.Spring.Security.admin.dto.response.AdminLoginResponse;

public interface AdminService {
    AdminLoginResponse adminLogin(AdminLoginRequest loginRequest);
}
