package com.bidmall.gateway.filter;

import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Component;

import io.jsonwebtoken.Claims;
import io.jsonwebtoken.Jwts;

@Component
public class JwtTokenProvider {

	@Value("${jwt.secret}")
	private String secret;

	@Value("${jwt.expiration}")
	private long expiration; // ms

	/**
	 * 토큰 파싱 및 검증
	 * @param token
	 * @return
	 */
	public Claims parsingToken(String token) {
		Claims claims = Jwts.parser()
			.setSigningKey(secret)
			.parseClaimsJws(token)
			.getBody();
		return claims;
	}
}
