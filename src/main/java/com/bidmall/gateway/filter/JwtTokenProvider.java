package com.bidmall.gateway.filter;

import java.util.Date;

import org.springframework.beans.factory.annotation.Value;
import org.springframework.boot.context.properties.ConfigurationProperties;
import org.springframework.stereotype.Component;

import io.jsonwebtoken.Claims;
import io.jsonwebtoken.ExpiredJwtException;
import io.jsonwebtoken.JwtException;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.MalformedJwtException;
import io.jsonwebtoken.SignatureException;

@Component("myJwtTokenProvider")
@ConfigurationProperties(prefix = "jwt")
public class JwtTokenProvider {

	@Value("${jwt.secret}")
	private String secret;

	/**
	 * 토큰 파싱 및 검증
	 */
	public Claims parsingToken(String token) {
		validateTokenFormat(token);
		Claims claims = parseToken(token);
		validateTokenExpiration(claims);
		return claims;
	}

	private void validateTokenFormat(String token) {
		if (token == null || token.trim().isEmpty()) {
			throw new JwtException("Token is null or empty");
		}

		if (!token.matches("^[A-Za-z0-9-_]+\\.[A-Za-z0-9-_]+\\.[A-Za-z0-9-_]+$")) {
			throw new JwtException("Invalid JWT format");
		}
	}

	/**
	 * 토큰만료시간 검증
	 * @param claims
	 */
	private void validateTokenExpiration(Claims claims) {
		Date expirationDate = claims.getExpiration();
		if (expirationDate != null && expirationDate.before(new Date())) {
			throw new JwtException("Token is expired");
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
