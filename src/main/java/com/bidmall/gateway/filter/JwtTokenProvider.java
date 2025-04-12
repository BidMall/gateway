package com.bidmall.gateway.filter;

import java.util.Date;

import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Component;

import io.jsonwebtoken.Claims;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.SignatureAlgorithm;

@Component
public class JwtTokenProvider {

	@Value("${jwt.secret}")
	private String secret;

	@Value("${jwt.expiration}")
	private long expiration; // ms

	public Claims parsingToken(String token) {
		Claims claims = Jwts.parser()
			.setSigningKey(secret)
			.parseClaimsJws(token)
			.getBody();
		return claims;
	}

	/**
	 * 토큰생성
	 */
	public String generateToken(String userId) {
		Date now = new Date();
		Date expiryDate = new Date(now.getTime() + expiration);
		return Jwts.builder()
			.setSubject(userId)
			.setIssuedAt(now)
			.setExpiration(expiryDate)
			.signWith(SignatureAlgorithm.HS256, secret)
			.compact();
	}
}
