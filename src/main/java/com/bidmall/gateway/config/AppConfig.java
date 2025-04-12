package com.bidmall.gateway.config;

import org.springframework.boot.context.properties.EnableConfigurationProperties;
import org.springframework.context.annotation.Configuration;

import com.bidmall.gateway.filter.JwtTokenProvider;

@Configuration
@EnableConfigurationProperties(JwtTokenProvider.class)
public class AppConfig {
}
