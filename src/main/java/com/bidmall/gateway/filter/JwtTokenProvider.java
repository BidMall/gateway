package com.bidmall.gateway.filter;

import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Component;

import io.jsonwebtoken.Claims;
import io.jsonwebtoken.ExpiredJwtException;
import io.jsonwebtoken.JwtException;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.MalformedJwtException;
import io.jsonwebtoken.SignatureException;

@Component
public class JwtTokenProvider {

	@Value("${jwt.secret}")
	private String secret;

	@Value("${jwt.expiration}")
	private long expiration; // ms

	/**
	 * 토큰 파싱 및 검증
	 */
	public Claims parsingToken(String token) {
		validateTokenFormat(token);
		return parseToken(token);
	}

	private void validateTokenFormat(String token) {
		if (token == null || token.trim().isEmpty()) {
			throw new JwtException("Token is null or empty");
		}

		if (!token.matches("^[A-Za-z0-9-_]+\\.[A-Za-z0-9-_]+\\.[A-Za-z0-9-_]+$")) {
			throw new JwtException("Invalid JWT format");
		}
	}

	private Claims parseToken(String token) {
		try {
			return Jwts.parser()
				.setSigningKey(secret)
				.parseClaimsJws(token)
				.getBody();
		} catch (ExpiredJwtException e) {
			throw new JwtException("Token is expired", e);
		} catch (SignatureException e) {
			throw new JwtException("Invalid signature", e);
		} catch (MalformedJwtException e) {
			throw new JwtException("Malformed token", e);
		}
	}
}
