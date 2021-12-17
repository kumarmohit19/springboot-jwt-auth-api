package com.securerestapi.repository;

import org.springframework.data.jpa.repository.JpaRepository;

import com.securerestapi.entity.UserEntity;

public interface UserJpaRepository extends JpaRepository<UserEntity, Long> {

	UserEntity findByUsername(String username);
}
