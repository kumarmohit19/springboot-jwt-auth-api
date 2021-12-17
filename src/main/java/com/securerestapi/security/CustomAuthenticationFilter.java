package com.securerestapi.security;

import java.io.IOException;
import java.util.HashMap;
import java.util.Map;
import java.util.stream.Collectors;

import javax.servlet.FilterChain;
import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import org.springframework.http.MediaType;
import org.springframework.http.HttpStatus;

import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.securerestapi.utility.JwtUtil;

import lombok.RequiredArgsConstructor;
import lombok.SneakyThrows;
import lombok.extern.slf4j.Slf4j;

@Slf4j
@RequiredArgsConstructor
public class CustomAuthenticationFilter extends UsernamePasswordAuthenticationFilter {

	private static final String BAD_CREDENTIAL_MESSAGE = "Authentication failed for username: %s and password: %s";

	private final AuthenticationManager authenticationManager;

	@SneakyThrows
	@Override
	public Authentication attemptAuthentication(HttpServletRequest request, HttpServletResponse response)
			throws AuthenticationException {

		String username = null;
		String password = null;
		try {
			ObjectMapper objectMapper = new ObjectMapper();
			Map<String, String> map = objectMapper.readValue(request.getInputStream(), Map.class);
			username = map.get("username");
			password = map.get("password");
			log.debug("Login with username: {}", username);
			return authenticationManager.authenticate(new UsernamePasswordAuthenticationToken(username, password));
		} catch (AuthenticationException e) {
			log.error(String.format(BAD_CREDENTIAL_MESSAGE, username, password), e);
			throw e;
		} catch (Exception e) {
			response.setStatus(HttpStatus.INTERNAL_SERVER_ERROR.value());
			Map<String, String> error = new HashMap<>();
			error.put("errorMessage", e.getMessage());
			response.setContentType(MediaType.APPLICATION_JSON_VALUE);
			new ObjectMapper().writeValue(response.getOutputStream(), error);
			throw new RuntimeException(String.format("Error in attemptAuthentication with username %s and password %s",
					username, password), e);
		}
	}

	@Override
	protected void successfulAuthentication(HttpServletRequest request, HttpServletResponse response, FilterChain chain,
			Authentication authentication) throws IOException, ServletException {
		User user = (User) authentication.getPrincipal();
		String accessToken = JwtUtil.createAccessToken(user.getUsername(), request.getRequestURL().toString(),
				user.getAuthorities().stream().map(GrantedAuthority::getAuthority).collect(Collectors.toList()));
		String refreshToken = JwtUtil.createRefreshToken(user.getUsername());
		response.addHeader("access_token", accessToken);
		response.addHeader("refresh_token", refreshToken);
	}

	@Override
	protected void unsuccessfulAuthentication(HttpServletRequest request, HttpServletResponse response,
			AuthenticationException failed) throws IOException, ServletException {
		response.setStatus(HttpServletResponse.SC_UNAUTHORIZED);
		ObjectMapper mapper = new ObjectMapper();
		Map<String, String> error = new HashMap<>();
		error.put("errorMessage", "Bad credentials");
		response.setContentType(MediaType.APPLICATION_JSON_VALUE);
		mapper.writeValue(response.getOutputStream(), error);
	}
}

/**
 * This filter is used in the login phase. It automatically calls UserDetailsService.loadUserByUsername, 
 * and if the user exists, it creates and returns two JWT tokens: one is the access token, used to authorize the user, the other is the refresh token, used by the client to acquire a new access token without having to login again.
 */

/**
 * The refresh token also has an expiration date, but obviously it is greater than that of the access token.
 */

/**
 * Let's analyze the code:
 * the attemptAuthentication method is invoked in the login phase, takes username and password from the RequestBody and calls authenticationManager.authenticate, which in turn calls UserDetailService to check that the user is present in the database, and then it checks that the decoded password of the User instance (created by UserDetailService) corresponds to the one given as input. If the checks are passed, the successfulAuthentication method is called, otherwise unsuccessfulAuthentication.
 * The successfulAuthentication method creates the access token and the refresh token and adds them to the response header of the /login call.
 * The unsuccessfulAuthentication method is invoked when attemptAuthentication throws an AuthenticationException type exception. Overriding this method, for our purposes, is optional. We use it to return 401 and an error message in the Response Body.
 * The JwtUtil class is a utility class that we will create to create and validate the JWT token.
 */
