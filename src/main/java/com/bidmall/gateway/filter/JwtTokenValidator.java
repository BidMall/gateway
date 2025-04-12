package com.bidmall.gateway.filter;

import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Component;

import io.jsonwebtoken.Claims;
import io.jsonwebtoken.Jws;
import io.jsonwebtoken.JwtException;
import io.jsonwebtoken.Jwts;

@Component
public class JwtTokenValidator {

	@Value("${jwt.secret}")
	private String secret;

	/**
	 * 생성된 토큰 검증
	 */
	public Claims validationToken(String token) {
		try {
			Jws<Claims> claims = Jwts.parser()
				.setSigningKey(secret)
				.parseClaimsJws(token);

			return claims.getBody();
		} catch (JwtException | IllegalArgumentException e) {
			throw new RuntimeException("유효하지 않은 JWT 토큰입니다.", e);
		}
	}
}
