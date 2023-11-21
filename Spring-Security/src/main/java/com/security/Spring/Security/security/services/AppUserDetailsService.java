package com.security.Spring.Security.security.services;

import com.security.Spring.Security.appUser.model.AppUser;
import com.security.Spring.Security.appUser.repository.AppUserRepository;
import com.security.Spring.Security.security.user.SecuredUser;
import lombok.AllArgsConstructor;
import lombok.RequiredArgsConstructor;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.stereotype.Service;

@Service
@RequiredArgsConstructor
public class AppUserDetailsService implements UserDetailsService {
    private final AppUserRepository appUserRepository;

    @Override
    public UserDetails loadUserByUsername(String email) throws UsernameNotFoundException {
    final AppUser appUser = appUserRepository.findByEmail(email).orElseThrow(
            ()-> new UsernameNotFoundException("User with this email not found"));
        return new SecuredUser(appUser);
    }
}
