package com.security.Spring.Security.manager.service;

import com.security.Spring.Security.appUser.dto.response.JwtResponse;
import com.security.Spring.Security.appUser.model.AppUser;
import com.security.Spring.Security.appUser.model.enums.Role;
import com.security.Spring.Security.appUser.service.AppUserService;
import com.security.Spring.Security.manager.dto.request.ManagerLoginRequest;
import com.security.Spring.Security.manager.dto.response.ManagerLoginResponse;
import com.security.Spring.Security.manager.model.Manager;
import com.security.Spring.Security.manager.repository.ManagerRepository;
import jakarta.annotation.PostConstruct;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;

@Service
@RequiredArgsConstructor
@Slf4j
public class ManagerServiceImpl implements ManagerService{
    private final AppUserService  appUserService;
    private final ManagerRepository managerRepository;
    private final PasswordEncoder passwordEncoder;

    @PostConstruct
    private void createManager(){
        if(managerRepository.count() == 0){
            AppUser appUser = new AppUser();
            appUser.setFirstName("Manager");
            appUser.setLastName("Manager");
            appUser.setEmail("manager@gmail.com");
            appUser.setPassword(passwordEncoder.encode("Password123$"));
            appUser.setEnabled(true);
            appUser.setRole(Role.MANAGER);

            Manager manager = new Manager();
            manager.setAppUser(appUser);

            managerRepository.save(manager);

//            JwtResponse jwtResponse = appUserService.generateJwtToken(appUser);
//            log.info("""
//                    %n::::::::::::::::::: Manager Access Token -> %s :::::::::::::::::::
//                    ::::::::::::::::::: Manager Refresh Token -> %s :::::::::::::::::::
//                    %n""".formatted(jwtResponse.getAccessToken(), jwtResponse.getRefreshToken()));
        }
    }
    @Override
    public ManagerLoginResponse managerLogin(ManagerLoginRequest loginRequest) {
        AppUser appUser = appUserService.authenticate(loginRequest.getEmail(), loginRequest.getPassword());
        appUserService.revokeAllUserTokens(appUser);
        JwtResponse jwtResponse = appUserService.generateJwtToken(appUser);
        return ManagerLoginResponse.builder()
                .message("Manager login successfully")
                .jwtResponse(jwtResponse)
                .build();
    }
}
