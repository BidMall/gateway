package com.bidmall.gateway.filter;

import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Component;

import io.jsonwebtoken.Claims;
import io.jsonwebtoken.JwtException;
import io.jsonwebtoken.Jwts;

@Component
public class JwtTokenParser {

	@Value("${jwt.secret}")
	private String secret;

	public Claims parseToken(String token) throws JwtException {
		return Jwts.parser()
			.setSigningKey(secret)
			.parseClaimsJws(token)
			.getBody();
	}
}
