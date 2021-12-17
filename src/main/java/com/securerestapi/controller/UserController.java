package com.securerestapi.controller;

import java.io.IOException;
import java.net.URI;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;
import org.springframework.web.servlet.support.ServletUriComponentsBuilder;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.securerestapi.dto.RoleDTO;
import com.securerestapi.entity.UserEntity;
import com.securerestapi.service.UserService;

import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;

import static org.springframework.http.HttpHeaders.AUTHORIZATION;
import static org.springframework.http.HttpStatus.FORBIDDEN;
import static org.springframework.util.MimeTypeUtils.APPLICATION_JSON_VALUE;

@RestController
@RequestMapping("/users")
@RequiredArgsConstructor
@Slf4j
public class UserController {

	private final UserService userService;

	@GetMapping
	public ResponseEntity<List<UserEntity>> findAll() {
		return ResponseEntity.ok().body(userService.findAll());
	}

	@GetMapping("/{username}")
	public ResponseEntity<UserEntity> findByUsername(@PathVariable String username) {
		return ResponseEntity.ok().body(userService.findByUsername(username));
	}

	@PostMapping
	public ResponseEntity<UserEntity> save(@RequestBody UserEntity user) {
		UserEntity userEntity = userService.save(user);
		URI uri = URI.create(ServletUriComponentsBuilder.fromCurrentRequest().path("/{username}")
				.buildAndExpand(userEntity.getUsername()).toUriString());
		return ResponseEntity.created(uri).build();
	}

	@PostMapping("/{username}/addRoleToUser")
	public ResponseEntity<?> addRoleToUser(@PathVariable String username, @RequestBody RoleDTO request) {
		UserEntity userEntity = userService.addRoleToUser(username, request.getRoleName());
		return ResponseEntity.ok(userEntity);
	}
	
	@GetMapping("/refreshToken")
	public void refreshToken(HttpServletRequest request, HttpServletResponse response) throws IOException {
		String authorizationHeader = request.getHeader(AUTHORIZATION);
		if (authorizationHeader != null && authorizationHeader.startsWith("Bearer ")) {
			try {
				Map<String, String> tokenMap = userService.refreshToken(authorizationHeader,
						request.getRequestURL().toString());
				response.addHeader("access_token", tokenMap.get("access_token"));
				response.addHeader("refresh_token", tokenMap.get("refresh_token"));
			} catch (Exception e) {
				log.error(String.format("Error refresh token: %s", authorizationHeader), e);
				response.setStatus(FORBIDDEN.value());
				Map<String, String> error = new HashMap<>();
				error.put("errorMessage", e.getMessage());
				response.setContentType(APPLICATION_JSON_VALUE);
				new ObjectMapper().writeValue(response.getOutputStream(), error);
			}
		} else {
			throw new RuntimeException("Refresh token is missing");
		}
	}
}