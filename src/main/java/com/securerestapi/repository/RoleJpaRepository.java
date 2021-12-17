package com.securerestapi.repository;

import org.springframework.data.jpa.repository.JpaRepository;

import com.securerestapi.entity.RoleEntity;

public interface RoleJpaRepository extends JpaRepository<RoleEntity, Long> {

	RoleEntity findByName(String name);
}

/**
 * Spring will create implementations of these two interfaces for us, with the DAO methods findAll, findById, etc.
 */
