package com.securerestapi.dto;

import lombok.Getter;
import lombok.Setter;

import javax.validation.constraints.NotBlank;

@Getter
@Setter
public class RoleDTO {

	@NotBlank
	private String roleName;
}
