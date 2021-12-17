package com.securerestapi.security;

import org.springframework.context.annotation.Configuration;
import org.springframework.http.HttpMethod;
import org.springframework.security.config.annotation.authentication.builders.AuthenticationManagerBuilder;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;

import lombok.RequiredArgsConstructor;

@Configuration
@EnableWebSecurity
@RequiredArgsConstructor
public class SecurityConfig extends WebSecurityConfigurerAdapter {

	private final UserDetailsService userDetailsService;
	private final BCryptPasswordEncoder bCryptPasswordEncoder;

	// we want to check users from db
	@Override
	protected void configure(AuthenticationManagerBuilder auth) throws Exception {
		auth.userDetailsService(userDetailsService).passwordEncoder(bCryptPasswordEncoder);
	}

	@Override
	protected void configure(HttpSecurity http) throws Exception {
		http.csrf().disable()
				.sessionManagement()
				.sessionCreationPolicy(SessionCreationPolicy.STATELESS).and()
				.authorizeRequests()
				.antMatchers(HttpMethod.POST, "/login/**")
				.permitAll()
				.and()
				.authorizeRequests()
				.antMatchers(HttpMethod.POST, "/users/**")
				.hasAuthority("ROLE_ADMIN")
				.and()
				.authorizeRequests()
				.anyRequest()
				.authenticated()
				.and()
				.addFilter(new CustomAuthenticationFilter(super.authenticationManagerBean()))
				.addFilterBefore(new CustomAuthorizationFilter(), UsernamePasswordAuthenticationFilter.class);

		http.headers().cacheControl();
	}
}

/**
 * The first step in customizing Spring Security is to create a class that extends WebSecurityConfigurerAdapter, 
 * so that it overrides the default behavior.
 */


/**
 * Let's analyze the configure(AuthenticationManagerBuilder auth) method:
 * here we indicate to Spring that as UserDetailService, which contains the loadUserByUsername method, a bean created by us must be used. In particular the bean created by us will search the user from db. 
 * Moreover to encode/decode the password must be used the PasswordEncoder bean we created earlier.
 * Let's analyze the void configure(HttpSecurity http) method:
 * With the first two lines, we disable the default check on CSRF attacks and tell Spring Security that it must not create a session for users who authenticate themselves (policy STATELESS).
 * With authorizeRequests().antMatchers(HttpMethod.POST, "/login/**").permitAll() we indicate to Spring Security that anyone can consume the /login API with a POST verb.
 * With authorizeRequests().antMatchers(HttpMethod.POST, "/users/**").hasAuthority("ROLE_ADMIN") we indicate to Spring Security that only users with role ADMIN can consume the /users/.. API with verb POST.
 * With authorizeRequests().anyRequest().authenticated() we indicate that all other requests can be consumed if the user is authenticated.
 * With addFilter(new CustomAuthenticationFilter(super.authenticationManagerBean())) we add a custom filter for the authentication phase; the custom class extends the UsernamePasswordAuthenticationFilter class of Spring Security, therefore, it is used only in the login phase.
 * With addFilterBefore(new CustomAuthorizationFilter(), UsernamePasswordAuthenticationFilter.class) we create a filter which is used for each HTTP request, before the UsernamePasswordAuthenticationFilter type, i.e. it is called before the CustomAuthenticationFilter class.
 */