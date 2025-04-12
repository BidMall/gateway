package com.bidmall.gateway.filter;

import org.springframework.http.server.reactive.ServerHttpRequest;
import org.springframework.web.server.ServerWebExchange;

import io.jsonwebtoken.Claims;

public class HeaderUtils {

	/**
	 *
	 * @param exchange
	 * @param claims
	 * @return
	 */
	public static ServerHttpRequest addHeader(ServerWebExchange exchange, Claims claims) {
		return exchange.getRequest().mutate()
			.header("X-User-Id", claims.getSubject())
			.build();
	}
}
