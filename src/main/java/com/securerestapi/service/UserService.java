package com.securerestapi.service;

import java.util.List;
import java.util.Map;

import com.nimbusds.jose.JOSEException;
import com.nimbusds.jose.proc.BadJOSEException;
import java.text.ParseException;
import com.securerestapi.entity.UserEntity;

public interface UserService {

	UserEntity save(UserEntity user);

	UserEntity addRoleToUser(String username, String roleName);

	List<UserEntity> findAll();

	UserEntity findByUsername(String username);

	Map<String, String> refreshToken(String authorizationHeader, String issuer)
			throws BadJOSEException, ParseException, JOSEException;

}
