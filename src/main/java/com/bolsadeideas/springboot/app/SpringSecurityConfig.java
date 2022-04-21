package com.bolsadeideas.springboot.app;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.annotation.authentication.builders.AuthenticationManagerBuilder;
import org.springframework.security.config.annotation.method.configuration.EnableGlobalMethodSecurity;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;

//import com.bolsadeideas.springboot.app.auth.handler.LoginSuccessHandler;
import com.bolsadeideas.springboot.app.models.services.JpaUserDetailsService;

@EnableGlobalMethodSecurity(securedEnabled = true, prePostEnabled = true)
@Configuration
public class SpringSecurityConfig extends WebSecurityConfigurerAdapter {

	//@Autowired
	//private LoginSuccessHandler successHandler;

	@Autowired
	private JpaUserDetailsService userDetailService;

	@Autowired
	private BCryptPasswordEncoder passwordEncoder;

	@Autowired
	public void configurerGlobal(AuthenticationManagerBuilder builder) throws Exception {
		builder.userDetailsService(this.userDetailService).passwordEncoder(this.passwordEncoder);
	}

	@Override
	protected void configure(HttpSecurity http) throws Exception {
		http.authorizeRequests()
				.antMatchers("/", "/css/**", "/js/**", "/images/**", "/listar**", "/locale").permitAll()
				.anyRequest().authenticated()
				/*
				.and().formLogin().successHandler(this.successHandler).loginPage("/login").permitAll()
				.and().logout().permitAll()
				.and().exceptionHandling()
				.accessDeniedPage("/error_403")
				*/
				.and()
				.csrf().disable()//Deshabilitamos la protección csrf por que no usaremos la protección del token csrf sino el JWT. Importante que no hayan explícitamente inputs con el csrf
				.sessionManagement().sessionCreationPolicy(SessionCreationPolicy.STATELESS);//Stateless (sin estado), con esto deshabilitamos el uso de sesiones ya que usaremos el JWT
	}

}
