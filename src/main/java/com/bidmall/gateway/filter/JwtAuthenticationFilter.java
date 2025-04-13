package com.bidmall.gateway.filter;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Qualifier;
import org.springframework.cloud.gateway.filter.GatewayFilterChain;
import org.springframework.cloud.gateway.filter.GlobalFilter;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpStatus;
import org.springframework.http.server.reactive.ServerHttpRequest;
import org.springframework.stereotype.Component;
import org.springframework.web.server.ServerWebExchange;

import io.jsonwebtoken.Claims;
import io.jsonwebtoken.JwtException;
import reactor.core.publisher.Mono;

@Component
public class JwtAuthenticationFilter implements GlobalFilter {

	private final JwtTokenProvider tokenProvider;

	@Autowired
	public JwtAuthenticationFilter(@Qualifier("myJwtTokenProvider") JwtTokenProvider tokenProvider) {
		this.tokenProvider = tokenProvider;
	}

	/**
	 * ServerWebExchange 요청(Request)과 응답(Response) 담아둠
	 * 콜백처리 Thread
	 * 현재코드 동기적인 방식 -> 비동기 처리
	 * Jmeter
	 *
	 * @param exchange the current server exchange
	 * @param chain provides a way to delegate to the next filter
	 * @return
	 */
	@Override
	public Mono<Void> filter(ServerWebExchange exchange, GatewayFilterChain chain) {
		ServerHttpRequest request = exchange.getRequest();
		String authHeader = request.getHeaders().getFirst(HttpHeaders.AUTHORIZATION);

		if (!hasValidAuthorizationHeader(authHeader)) {
			return unauthorized(exchange);
		}
		String token = extractToken(authHeader);
		try {
			Claims claims = tokenProvider.parsingToken(token);
			validateSubjectAndIssuer(claims);
			ServerHttpRequest mutatedRequest = HeaderUtils.addHeader(exchange, claims);
			ServerWebExchange mutateExchange = exchange.mutate()
				.request(mutatedRequest)
				.build();
			return chain.filter(mutateExchange);
		} catch (JwtException e) {
			return unauthorized(exchange);
		}
	}

	private boolean hasValidAuthorizationHeader(String authHeader) {
		return authHeader != null && authHeader.startsWith("Bearer ");
	}

	private String extractToken(String authHeader) {
		return authHeader.substring(7);
	}

	private void validateSubjectAndIssuer(Claims claims) {
		if (claims.getSubject() == null || claims.getSubject().isEmpty()) {
			throw new JwtException("Invalid token: missing subject");
		}

		if (!"bidmall-user-service".equals(claims.getIssuer())) {
			throw new JwtException("Invalid token: unknown issuer");
		}
	}

	private Mono<Void> unauthorized(ServerWebExchange exchange) {
		exchange.getResponse().setStatusCode(HttpStatus.UNAUTHORIZED);
		return exchange.getResponse().setComplete();
	}
}
