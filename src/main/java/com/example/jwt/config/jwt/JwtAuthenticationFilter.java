package com.example.jwt.config.jwt;

import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;

// 스프링 시큐리티에서 UsernamePAsswordAuthenticationFilter 가 있음
// /login 요청해서 username, password 전송하면 (post)
// UsernamePAsswordAuthenticationFilter 가 동작함
public class JwtAuthenticationFilter extends UsernamePasswordAuthenticationFilter {
}
