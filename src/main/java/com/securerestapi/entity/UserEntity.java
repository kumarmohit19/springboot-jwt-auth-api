package com.securerestapi.entity;

import java.io.Serializable;
import java.util.ArrayList;
import java.util.Collection;

import javax.persistence.Column;
import javax.persistence.Entity;
import javax.persistence.GeneratedValue;
import javax.persistence.Id;
import javax.persistence.ManyToMany;
import javax.persistence.Table;

import lombok.AllArgsConstructor;
import lombok.Data;
import lombok.NoArgsConstructor;

@Entity
@Table(name = "USERS")
@Data
@NoArgsConstructor
@AllArgsConstructor
public class UserEntity implements Serializable {

	/**
	 * 
	 */
	private static final long serialVersionUID = 1L;

	@Id
	@GeneratedValue
	private Long id;

	@Column(unique = true, nullable = false)
	private String username;

	@Column(nullable = false)
	private String password;

	@ManyToMany
	private Collection<RoleEntity> roles = new ArrayList<>();
}


/**
 * With @Entity, we indicate to JPA that this Java class maps a table to DB.
 * With @Table, we indicate to JPA the name of the table.
 * With @Id and @GeneratedValue, we indicate to JPA that the annotated attribute is a primary key, which must be auto-generated.
 * With @Column(unique = true, nullable = false) we tell JPA that, when it generates the tables in DB, it must also create the unique and not null constraints for the annotated field.
 * With @ManyToMany we indicate to JPA that USERS is in a N:N relationship with ROLES (a one-way relationship, with EAGER fetch, i.e. every time we request a user from the USERS table, we will also fetch all his roles from the ROLES table).
 * The other annotations are from the Lombok library, which allows for cleaner code writing.
 */
