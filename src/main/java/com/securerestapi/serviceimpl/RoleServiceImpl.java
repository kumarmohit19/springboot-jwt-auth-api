package com.securerestapi.serviceimpl;

import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import com.securerestapi.entity.RoleEntity;
import com.securerestapi.entity.UserEntity;
import com.securerestapi.repository.RoleJpaRepository;
import com.securerestapi.repository.UserJpaRepository;
import com.securerestapi.service.RoleService;

import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;

@Service
@Transactional
@RequiredArgsConstructor
@Slf4j
public class RoleServiceImpl implements RoleService {

	private final UserJpaRepository userJpaRepository;
	private final RoleJpaRepository roleJpaRepository;
	
	@Override
	public RoleEntity save(RoleEntity roleEntity) {
		log.info("Saving role {} to the database");
		return roleJpaRepository.save(roleEntity);
		
	}
}
