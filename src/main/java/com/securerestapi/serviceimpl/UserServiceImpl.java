package com.securerestapi.serviceimpl;

import java.util.ArrayList;
import java.util.Collection;
import java.util.List;
import java.util.Map;
import java.util.stream.Collectors;

import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.text.ParseException;

import com.nimbusds.jose.JOSEException;
import com.nimbusds.jose.proc.BadJOSEException;
import com.securerestapi.entity.RoleEntity;
import com.securerestapi.entity.UserEntity;
import com.securerestapi.repository.RoleJpaRepository;
import com.securerestapi.repository.UserJpaRepository;
import com.securerestapi.service.UserService;
import com.securerestapi.utility.JwtUtil;

import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;

@Service
@Transactional
@RequiredArgsConstructor
@Slf4j
public class UserServiceImpl implements UserService, UserDetailsService  {

	private static final String USER_NOT_FOUND_MESSAGE = "User with username %s not found";

	private final UserJpaRepository userJpaRepository;
	private final RoleJpaRepository roleJpaRepository;
	private final PasswordEncoder passwordEncoder;

	@Override
	public UserEntity save(UserEntity user) {
		log.info("Saving user {} to the database", user.getUsername());
		user.setPassword(passwordEncoder.encode(user.getPassword()));
		return userJpaRepository.save(user);
	}

	@Override
	public UserEntity addRoleToUser(String username, String roleName) {
		log.info("Adding role {} to user {}", roleName, username);
		UserEntity userEntity = userJpaRepository.findByUsername(username);
		RoleEntity roleEntity = roleJpaRepository.findByName(roleName);
		userEntity.getRoles().add(roleEntity);
		return userEntity;
	}

	// findAll, findByUsername...

	@Transactional(readOnly = true)
	@Override
	public UserDetails loadUserByUsername(String username) throws UsernameNotFoundException {
		UserEntity user = userJpaRepository.findByUsername(username);
		if (user == null) {
			String message = String.format(USER_NOT_FOUND_MESSAGE, username);
			log.error(message);
			throw new UsernameNotFoundException(message);
		} else {
			log.debug("User found in the database: {}", username);
			Collection<SimpleGrantedAuthority> authorities = new ArrayList<>();
			user.getRoles().forEach(role -> {
				authorities.add(new SimpleGrantedAuthority(role.getName()));
			});
			return new User(user.getUsername(), user.getPassword(), authorities);
		}
	}

	@Transactional(readOnly = true)
	@Override
	public UserEntity findByUsername(String username) {
		log.info("Retrieving user {}", username);
		return userJpaRepository.findByUsername(username);
	}

	@Transactional(readOnly = true)
	@Override
	public List<UserEntity> findAll() {
		log.info("Retrieving all users");
		return userJpaRepository.findAll();
	}

	@Transactional(readOnly = true)
	@Override
	public Map<String, String> refreshToken(String authorizationHeader, String issuer)
			throws BadJOSEException, JOSEException, ParseException {

		String refreshToken = authorizationHeader.substring("Bearer ".length());
		UsernamePasswordAuthenticationToken authenticationToken = JwtUtil.parseToken(refreshToken);
		String username = authenticationToken.getName();
		UserEntity userEntity = findByUsername(username);
		List<String> roles = userEntity.getRoles().stream().map(RoleEntity::getName).collect(Collectors.toList());
		String accessToken = JwtUtil.createAccessToken(username, issuer, roles);
		return Map.of("access_token", accessToken, "refresh_token", refreshToken);
	}
}

/**
 * With @Service we indicate to Spring that the class is a bean with business logic.
 * With @Transactional we indicate to Spring that all methods of the class are transactional.
 * @RequiredArgsConstructor and @Slf4j are two annotations from the Lombok library, which allow us to autogenerate a constructor based on final fields, and create a logger, respectively.
 * The save method, in addition to trivially calling the save method of the repository, encodes the password before saving to db. We will next create a bean of type PasswordEncoder.
 * The addRoleToUser method allows you to add an existing role to an existing user. 
 * The save method of UserJpaRepository is not invoked as userEntity is already a managed entity, being in transaction, and therefore all its modifications after the findByUsername are saved.
 */

/**
 * Instead of creating a new class that implements the UserDetailService interface, we make implement this last one directly to the UserServiceImpl class:
 */

/**
 * The loadUserByUsername method simply looks up the user with username in input, on the DB.
 * If it exists, it transforms RoleEntity roles into SimpleGrantedAuthority, which is the default Spring Security class for managing roles and finally returns an instance of type User, which is a Spring Security class that implements UserDetails.
 * If the user does not exist, an exception of type UsernameNotFoundException is thrown.
 */
