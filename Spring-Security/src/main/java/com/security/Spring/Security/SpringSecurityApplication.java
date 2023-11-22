package com.security.Spring.Security;

import com.security.Spring.Security.admin.dto.request.AdminLoginRequest;
import com.security.Spring.Security.admin.dto.response.AdminLoginResponse;
import com.security.Spring.Security.admin.service.AdminService;
import com.security.Spring.Security.manager.dto.request.ManagerLoginRequest;
import com.security.Spring.Security.manager.dto.response.ManagerLoginResponse;
import com.security.Spring.Security.manager.service.ManagerService;
import org.springframework.boot.CommandLineRunner;
import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.context.annotation.Bean;

@SpringBootApplication
public class SpringSecurityApplication {

	public static void main(String[] args) {
		SpringApplication.run(SpringSecurityApplication.class, args);
	}

	@Bean
	public CommandLineRunner commandLineRunner(AdminService adminService, ManagerService managerService){
		return args -> {
			AdminLoginRequest adminLoginRequest = new AdminLoginRequest();
			adminLoginRequest.setEmail("admin@Gmail.com");
			adminLoginRequest.setPassword("Password123$");
			AdminLoginResponse adminLoginResponse = adminService.adminLogin(adminLoginRequest);

			ManagerLoginRequest managerLoginRequest = new ManagerLoginRequest();
			managerLoginRequest.setEmail("manager@gmail.com");
			managerLoginRequest.setPassword("Password123$");
			ManagerLoginResponse managerLoginResponse = managerService.managerLogin(managerLoginRequest);

			System.out.printf("%n%n::::::::::::Admin Access Token-> %s%n%n",adminLoginResponse.getJwtResponse().getAccessToken());
			System.out.printf("::::::::::::Manager Access Token-> %s%n%n",managerLoginResponse.getJwtResponse().getAccessToken());
		};
	}
}
