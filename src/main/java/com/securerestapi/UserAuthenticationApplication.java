package com.securerestapi;

import java.util.ArrayList;

import org.springframework.boot.CommandLineRunner;
import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.context.annotation.Bean;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;

import com.securerestapi.entity.RoleEntity;
import com.securerestapi.entity.UserEntity;
import com.securerestapi.service.RoleService;
import com.securerestapi.service.UserService;

@SpringBootApplication
public class UserAuthenticationApplication {

	public static void main(String[] args) {
		SpringApplication.run(UserAuthenticationApplication.class, args);
	}

	@Bean
	PasswordEncoder passwordEncoder() {
		return new BCryptPasswordEncoder();
	}

	@Bean
	CommandLineRunner run(UserService userService, RoleService roleService) {
		return args -> {
			roleService.save(new RoleEntity(null, "ROLE_USER"));
			roleService.save(new RoleEntity(null, "ROLE_ADMIN"));

			userService.save(new UserEntity(null, "mohit", "12345", new ArrayList<>()));
			userService.save(new UserEntity(null, "harsh", "12345", new ArrayList<>()));

			userService.addRoleToUser("harsh", "ROLE_USER");
			userService.addRoleToUser("mohit", "ROLE_ADMIN");
			userService.addRoleToUser("mohit", "ROLE_USER");
		};
	}

}
