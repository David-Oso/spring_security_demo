package com.security.Spring.Security.admin.service;

import com.security.Spring.Security.admin.dto.request.AdminLoginRequest;
import com.security.Spring.Security.admin.dto.response.AdminLoginResponse;
import com.security.Spring.Security.admin.model.Admin;
import com.security.Spring.Security.admin.repository.AdminRepository;
import com.security.Spring.Security.appUser.dto.response.JwtResponse;
import com.security.Spring.Security.appUser.model.AppUser;
import com.security.Spring.Security.appUser.model.enums.Role;
import com.security.Spring.Security.appUser.service.AppUserService;
import jakarta.annotation.PostConstruct;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;

@Service
@RequiredArgsConstructor
@Slf4j
public class AdminServiceImpl implements AdminService {
    private final AppUserService  appUserService;
    private final AdminRepository adminRepository;
    private final PasswordEncoder passwordEncoder;

    @PostConstruct
    private void createManager(){
        if(adminRepository.count() == 0){
            AppUser appUser = new AppUser();
            appUser.setFirstName("Admin");
            appUser.setLastName("Admin");
            appUser.setEmail("admin@gmail.com");
            appUser.setPassword(passwordEncoder.encode("Password123$"));
            appUser.setEnabled(true);
            appUser.setRole(Role.ADMIN);

            Admin admin = new Admin();
            admin.setAppUser(appUser);

            adminRepository.save(admin);

            JwtResponse jwtResponse = appUserService.generateJwtToken(appUser);
            log.info("""
                    %n::::::::::::::::::: Admin Access Token -> %s :::::::::::::::::::
                    ::::::::::::::::::: Admin Refresh Token -> %s :::::::::::::::::::
                    %n""".formatted(jwtResponse.getAccessToken(), jwtResponse.getRefreshToken()));
        }
    }
    @Override
    public AdminLoginResponse adminLogin(AdminLoginRequest loginRequest) {
        AppUser appUser = appUserService.authenticate(loginRequest.getEmail(), loginRequest.getPassword());
        appUserService.revokeAllUserTokens(appUser);
        JwtResponse jwtResponse = appUserService.generateJwtToken(appUser);
        return AdminLoginResponse.builder()
                .message("Manager login successfully")
                .jwtResponse(jwtResponse)
                .build();
    }
}
