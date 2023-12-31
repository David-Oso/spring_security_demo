package com.security.Spring.Security.security.services;

import com.security.Spring.Security.appUser.model.AppUser;
import com.security.Spring.Security.security.token.TokenRepository;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import lombok.RequiredArgsConstructor;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.web.authentication.logout.LogoutHandler;
import org.springframework.stereotype.Service;


import static org.springframework.http.HttpHeaders.AUTHORIZATION;

@Service
@RequiredArgsConstructor
public class LogoutService implements LogoutHandler {
    private final TokenRepository tokenRepository;
    @Override
    public void logout(HttpServletRequest request, HttpServletResponse response, Authentication authentication) {
        final String authHeader = request.getHeader(AUTHORIZATION);
        if(authHeader == null || !authHeader.startsWith("Bearer ")){
            return;
        }
        String jwt = authHeader.substring(7);
        var storedToken = tokenRepository.findByAccessToken(jwt)
                .orElse(null);
        if(storedToken != null){
            AppUser appUser = storedToken.getAppUser();
            var tokens = tokenRepository.findAllByAppUser_Id(appUser.getId());
            tokenRepository.deleteAll(tokens);
//            storedToken.setExpired(true);
//            storedToken.setRevoked(true);
//            tokenRepository.save(storedToken);
            SecurityContextHolder.clearContext();
        }
    }
}
