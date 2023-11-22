package com.security.Spring.Security.user.service;

import com.security.Spring.Security.appUser.dto.request.ChangePasswordRequest;
import com.security.Spring.Security.appUser.dto.response.ChangePasswordResponse;
import com.security.Spring.Security.appUser.dto.response.JwtResponse;
import com.security.Spring.Security.appUser.model.AppUser;
import com.security.Spring.Security.appUser.model.enums.Role;
import com.security.Spring.Security.appUser.service.AppUserService;
import com.security.Spring.Security.user.dto.request.LoginRequest;
import com.security.Spring.Security.user.dto.request.RegisterRequest;
import com.security.Spring.Security.user.dto.response.LoginResponse;
import com.security.Spring.Security.user.dto.response.RegisterResponse;
import com.security.Spring.Security.user.model.User;
import com.security.Spring.Security.user.repository.UserRepository;
import lombok.RequiredArgsConstructor;
import org.modelmapper.ModelMapper;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;

import java.security.Principal;

@Service
@RequiredArgsConstructor
public class userServiceImpl implements UserService{
    private final UserRepository userRepository;
    private final PasswordEncoder passwordEncoder;
    private final AppUserService appUserService;
    private final ModelMapper modelMapper;
    @Override
    public RegisterResponse registerUser(RegisterRequest registerRequest) {
        AppUser appUser = modelMapper.map(registerRequest, AppUser.class);
        appUser.setPassword(passwordEncoder.encode(registerRequest.getPassword()));
        appUser.setRole(Role.USER);
        User user = new User();
        user.setAppUser(appUser);
        user.setGender(registerRequest.getGender());
        userRepository.save(user);
        return RegisterResponse.builder()
                .message("User registered successfully")
                .isEnabled(false)
                .build();
    }

    @Override
    public LoginResponse login(LoginRequest loginRequest) {
        AppUser appUser = appUserService.authenticate(loginRequest.getEmail(), loginRequest.getPassword());
        appUserService.revokeAllUserTokens(appUser);
        JwtResponse jwtResponse = appUserService.generateJwtToken(appUser);
        return LoginResponse.builder()
                .message("User authenticated successfully")
                .jwtResponse(jwtResponse)
                .build();
    }

    @Override
    public ChangePasswordResponse changePassword(ChangePasswordRequest changePasswordRequest, Principal user) {
        return appUserService.changePassword(changePasswordRequest, user);
    }
}
