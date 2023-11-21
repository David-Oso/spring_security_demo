package com.security.Spring.Security.appUser.service;

import com.security.Spring.Security.appUser.model.AppUser;
import com.security.Spring.Security.appUser.dto.request.ChangePasswordRequest;
import com.security.Spring.Security.appUser.dto.response.ChangePasswordResponse;
import com.security.Spring.Security.appUser.repository.AppUserRepository;
import lombok.RequiredArgsConstructor;
import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;

import java.security.Principal;

@Service
@RequiredArgsConstructor
public class AppUserServiceImpl implements AppUserService {
    private final PasswordEncoder passwordEncoder;
    private final AppUserRepository appUserRepository;
    @Override
    public ChangePasswordResponse changePassword(ChangePasswordRequest request, Principal connectedUser) {
        AppUser appUser = (AppUser) ((UsernamePasswordAuthenticationToken)connectedUser).getPrincipal();
        checkIfCurrentPasswordIsCorrect(request.getCurrentPassword(), appUser.getPassword());
        checkIfTwoPasswordAreTheSame(request.getNewPassword(), request.getConfirmPassword());
        appUser.setPassword(passwordEncoder.encode(request.getNewPassword()));
        appUserRepository.save(appUser);
        return ChangePasswordResponse.builder()
                .message("Password changed successfully")
                .build();
    }

    private void checkIfCurrentPasswordIsCorrect(String currentPassword, String appUserPassword) {
        if(!passwordEncoder.matches(currentPassword, appUserPassword))
            throw new BadCredentialsException("Wrong password");
    }

    private void checkIfTwoPasswordAreTheSame(String newPassword, String confirmPassword){
        if(!newPassword.equals(confirmPassword))
            throw new BadCredentialsException("Password are not the same");
    }
}
