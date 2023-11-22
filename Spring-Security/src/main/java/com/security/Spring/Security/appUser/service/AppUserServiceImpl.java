package com.security.Spring.Security.appUser.service;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.security.Spring.Security.appUser.dto.response.JwtResponse;
import com.security.Spring.Security.appUser.model.AppUser;
import com.security.Spring.Security.appUser.dto.request.ChangePasswordRequest;
import com.security.Spring.Security.appUser.dto.response.ChangePasswordResponse;
import com.security.Spring.Security.appUser.repository.AppUserRepository;
import com.security.Spring.Security.security.services.JwtService;
import com.security.Spring.Security.security.token.Token;
import com.security.Spring.Security.security.token.TokenRepository;
import com.security.Spring.Security.security.user.SecuredUser;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import lombok.RequiredArgsConstructor;
import org.springframework.http.HttpHeaders;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;

import java.io.IOException;
import java.security.Principal;
import java.util.List;

@Service
@RequiredArgsConstructor
public class AppUserServiceImpl implements AppUserService {
    private final PasswordEncoder passwordEncoder;
    private final AppUserRepository appUserRepository;
    private final AuthenticationManager authenticationManager;
    private final JwtService jwtService;
    private final TokenRepository tokenRepository;
    @Override
    public ChangePasswordResponse changePassword(ChangePasswordRequest request, Principal connectedUser) {
        SecuredUser securedUser = (SecuredUser) ((UsernamePasswordAuthenticationToken)connectedUser).getPrincipal();
        AppUser appUser = securedUser.getAppUser();
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

    @Override
    public JwtResponse generateJwtToken(AppUser appUser) {
        final String email = appUser.getEmail();
        final String accessToken = jwtService.generateAccessToken(email);
        final String refreshToken = jwtService.generateRefreshToken(email);
        saveToken(appUser, accessToken, refreshToken);
        return JwtResponse.builder()
                .accessToken(accessToken)
                .refreshToken(refreshToken)
                .build();
    }

    private void saveToken(AppUser appUser, String accessToken, String refreshToken) {
        final Token token = new Token();
        token.setAccessToken(accessToken);
        token.setRefreshToken(refreshToken);
        token.setAppUser(appUser);
        token.setRevoked(false);
        token.setExpired(false);
        tokenRepository.save(token);
    }

    @Override
    public AppUser authenticate(String email, String password) {
        Authentication authentication = authenticationManager.authenticate(
                new UsernamePasswordAuthenticationToken(email, password));
        String userEmail = authentication.getName();
        return getAppUserByEmail(userEmail);
    }

    private AppUser getAppUserByEmail(String email){
        return appUserRepository.findByEmail(email).orElseThrow(
                ()-> new UsernameNotFoundException("User not found"));
    }

    @Override
    public void revokeAllUserTokens(AppUser appUser) {
        List<Token> validUserTokens = tokenRepository.findAllValidTokenByUser(appUser.getId());
        if(validUserTokens.isEmpty())
            return;
        validUserTokens.forEach(token -> {
            token.setExpired(true);
            token.setRevoked(true);
        });
        tokenRepository.saveAll(validUserTokens);
    }

    @Override
    public void refreshToken(
            HttpServletRequest request,
            HttpServletResponse response) throws IOException {
        final String authHeader = request.getHeader(HttpHeaders.AUTHORIZATION);
        final String refreshToken;
        final String userEmail;
        if(authHeader == null || !authHeader.startsWith("Bearer "))
            return;
        refreshToken = authHeader.substring(7);
        userEmail = jwtService.extractUsername(refreshToken);
        if(userEmail != null){
            AppUser appUser = getAppUserByEmail(userEmail);
            if(jwtService.isValidToken(refreshToken, userEmail)){
                String accessToken = jwtService.generateAccessToken(userEmail);
                revokeAllUserTokens(appUser);
                saveToken(appUser, accessToken, refreshToken);
                var jwtResponse = JwtResponse.builder()
                        .accessToken(accessToken)
                        .refreshToken(refreshToken)
                        .build();
                new ObjectMapper().writeValue(response.getOutputStream(), jwtResponse);
            }
        }
    }

}
