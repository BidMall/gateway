package com.bidmall.gateway.filter;

import org.springframework.beans.factory.annotation.Value;
import org.springframework.cloud.gateway.filter.GatewayFilterChain;
import org.springframework.cloud.gateway.filter.GlobalFilter;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpStatus;
import org.springframework.http.server.reactive.ServerHttpRequest;
import org.springframework.stereotype.Component;
import org.springframework.web.server.ServerWebExchange;

import io.jsonwebtoken.Claims;
import io.jsonwebtoken.JwtException;
import lombok.RequiredArgsConstructor;
import reactor.core.publisher.Mono;

@Component
@RequiredArgsConstructor
public class JwtAuthenticationFilter implements GlobalFilter {

	@Value("${jwt.secret}")
	private String secret;

	private final JwtTokenProvider tokenProvider;

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
			validateClaims(claims);
			ServerHttpRequest mutatedRequest = HeaderUtils.addHeader(exchange, claims);
			return chain.filter(exchange.mutate().request(mutatedRequest).build());
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

	private void validateClaims(Claims claims) {
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
