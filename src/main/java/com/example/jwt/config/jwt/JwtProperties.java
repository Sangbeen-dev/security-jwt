package com.example.jwt.config.jwt;

public interface JwtProperties {
    String SECRET = "been";
    int EXPIRATION_TIME = 6000*10;
    String TOKEN_PREFIX = "Bearer ";
    String HEADER_STRING = "Authorization";
}
