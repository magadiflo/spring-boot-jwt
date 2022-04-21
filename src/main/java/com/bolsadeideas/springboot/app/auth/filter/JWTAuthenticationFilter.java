package com.bolsadeideas.springboot.app.auth.filter;

import java.io.IOException;
import java.util.Collection;
import java.util.Date;
import java.util.HashMap;
import java.util.Map;

import javax.servlet.FilterChain;
import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;
import org.springframework.security.web.util.matcher.AntPathRequestMatcher;

import com.fasterxml.jackson.databind.ObjectMapper;

import io.jsonwebtoken.Claims;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.SignatureAlgorithm;

public class JWTAuthenticationFilter extends UsernamePasswordAuthenticationFilter {

	private AuthenticationManager authenticationManager;

	public JWTAuthenticationFilter(AuthenticationManager authenticationManager) {
		this.authenticationManager = authenticationManager;
		this.setRequiresAuthenticationRequestMatcher(new AntPathRequestMatcher("/api/login", "POST"));
	}

	@Override
	public Authentication attemptAuthentication(HttpServletRequest request, HttpServletResponse response)
			throws AuthenticationException {

		String username = obtainUsername(request);
		String password = obtainPassword(request);
		username = (username != null) ? username.trim() : "";
		password = (password != null) ? password : "";

		if (username != null && password != null) {
			this.logger.info("Username desde request parameter (form-data): " + username);
			this.logger.info("Password desde request parameter (form-data): " + password);
		}

		UsernamePasswordAuthenticationToken authToken = new UsernamePasswordAuthenticationToken(username, password);

		return this.authenticationManager.authenticate(authToken);
	}

	@Override
	protected void successfulAuthentication(HttpServletRequest request, HttpServletResponse response, FilterChain chain,
			Authentication authResult) throws IOException, ServletException {
		
		Collection<? extends GrantedAuthority> roles = authResult.getAuthorities();
		Claims claims = Jwts.claims();
		claims.put("authorities", new ObjectMapper().writeValueAsString(roles)); //new ObjectMapper().writeValueAsString(roles), convertimos el objeto roles a un formato JSON
		
		String username = ((User) authResult.getPrincipal()).getUsername();
		String token = Jwts.builder()
				.setClaims(claims)
				.setSubject(username)
				.signWith(SignatureAlgorithm.HS512, "Alguna.Clave.Secreta.12345".getBytes())
				.setIssuedAt(new Date())
				.setExpiration(new Date(System.currentTimeMillis() + 3600000L))
				.compact();

		/**
		 * Importante que el nombre del paráemtro sea Authorization y el 
		 * valor como estándar debe iniciar con el prefijo Bearer 
		 */
		response.addHeader("Authorization", "Bearer " + token);
		
		Map<String, Object> body = new HashMap<>();
		body.put("token", token);
		body.put("user", (User) authResult.getPrincipal());
		body.put("mensaje", String.format("Hola %s, has iniciado sesión con éxito", username));
		
		response.getWriter().write(new ObjectMapper().writeValueAsString(body));
		response.setStatus(200);
		response.setContentType("application/json");
	}

}
