package com.bidmall.gateway.filter;

import java.util.Date;

import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Component;

import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.SignatureAlgorithm;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;

@Component
@Slf4j
@RequiredArgsConstructor
public class TokenProvider {

	private final JwtTokenValidator jwtTokenValidator;

	@Value("${jwt.secret}")
	private String secret;

	@Value("${jwt.expiration}")
	private long expiration;

	/**
	 * 토큰생성
	 * @param userId
	 * @return 생성된 토큰
	 */
	public String createToken(String userId) {
		String createToken = Jwts.builder()
			.setSubject(userId)
			.setExpiration(new Date(System.currentTimeMillis() + expiration))
			.signWith(SignatureAlgorithm.HS512, secret)
			.compact();

		try {
			jwtTokenValidator.validationToken(createToken);
		} catch (Exception e) {
			log.error("토큰 검증 실패: {}", e.getMessage());
			throw new RuntimeException("토큰 검증 실패", e);
		}
		return createToken;
	}
}
