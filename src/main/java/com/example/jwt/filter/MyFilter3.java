package com.example.jwt.filter;

import javax.servlet.*;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;
import java.io.PrintWriter;

public class MyFilter3 implements Filter {
    @Override
    public void doFilter(ServletRequest request
            , ServletResponse response, FilterChain filterChain) throws IOException, ServletException {
        HttpServletRequest req = (HttpServletRequest) request;
        HttpServletResponse res = (HttpServletResponse) response;
        // 토큰 : id pw 정상적으로 들어와서 로그인이 완료 되면 토큰을 만들고 그걸 응답
        // 요청할 때 마다 header에 Authorization에 value값으로 토큰을 가지고 오면
        // 토큰 검증 (RSA, HS256)
        if (req.getMethod().equals("POST")) {
            System.out.println("post 요청됨");
            String headerAuth = req.getHeader("Authorization");
            System.out.println(headerAuth);
            System.out.println("필터3");

            if (headerAuth.equals("auth")) {
                filterChain.doFilter(req, res);
            } else {
                PrintWriter out = res.getWriter();
                out.println("인증 안됨");
            }
        }
    }
}
