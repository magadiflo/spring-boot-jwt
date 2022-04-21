package com.bolsadeideas.springboot.app.auth.filter;

import java.io.IOException;

import javax.servlet.FilterChain;
import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.web.authentication.www.BasicAuthenticationFilter;

import io.jsonwebtoken.Claims;
import io.jsonwebtoken.JwtException;
import io.jsonwebtoken.Jwts;

public class JWTAuthorizationFilter extends BasicAuthenticationFilter {

	public JWTAuthorizationFilter(AuthenticationManager authenticationManager) {
		super(authenticationManager);

	}

	@Override
	protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response, FilterChain chain)
			throws IOException, ServletException {

		String header = request.getHeader("Authorization");
		if (!this.requriresAuthentication(header)) {
			chain.doFilter(request, response);
			return;
		}
		
		boolean validoToken;
		Claims token = null;
		try {
			token = Jwts.parser()
				.setSigningKey("Alguna.Clave.Secreta.12345".getBytes())
				.parseClaimsJws(header.replace("Bearer ", ""))
				.getBody();
			validoToken = true;
		} catch (JwtException | IllegalArgumentException e) {
			validoToken = false;
		}
		
		if(validoToken) {
			
		}

	}

	protected boolean requriresAuthentication(String header) {
		return !(header == null || !header.startsWith("Bearer "));
	}

}
