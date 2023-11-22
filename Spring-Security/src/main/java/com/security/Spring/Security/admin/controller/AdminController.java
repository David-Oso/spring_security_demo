package com.security.Spring.Security.admin.controller;

import com.security.Spring.Security.admin.dto.request.AdminLoginRequest;
import com.security.Spring.Security.admin.dto.response.AdminLoginResponse;
import com.security.Spring.Security.admin.service.AdminService;
import io.swagger.v3.oas.annotations.parameters.RequestBody;
import jakarta.validation.Valid;
import lombok.RequiredArgsConstructor;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;

@RestController
@RequestMapping("/admin")
@RequiredArgsConstructor
public class AdminController {
    private final AdminService adminService;

    @GetMapping
    public String get() {
        return "GET:: admin controller";
    }
    @PostMapping
    public String post() {
        return "POST:: admin controller";
    }
    @PutMapping
    public String put() {
        return "PUT:: admin controller";
    }
    @DeleteMapping
    public String delete() {
        return "DELETE:: admin controller";
    }

    @PostMapping("login")
    public ResponseEntity<?> managerLogin(@Valid @RequestBody AdminLoginRequest loginRequest){
        AdminLoginResponse adminLoginResponse = adminService.adminLogin(loginRequest);
        return ResponseEntity.ok(adminLoginResponse);
    }
}
