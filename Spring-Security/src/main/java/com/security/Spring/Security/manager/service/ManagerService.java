package com.security.Spring.Security.manager.service;

import com.security.Spring.Security.manager.dto.request.ManagerLoginRequest;
import com.security.Spring.Security.manager.dto.response.ManagerLoginResponse;

public interface ManagerService {
    ManagerLoginResponse managerLogin(ManagerLoginRequest loginRequest);
}
