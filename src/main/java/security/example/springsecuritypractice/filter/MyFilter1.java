package security.example.springsecuritypractice.filter;


import jakarta.servlet.*;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;

import java.io.IOException;
import java.io.PrintWriter;

public class MyFilter1 implements Filter {
    @Override
    public void doFilter(ServletRequest request, ServletResponse response, FilterChain chain) throws IOException, ServletException {
        HttpServletRequest req = (HttpServletRequest) request;
        HttpServletResponse res = (HttpServletResponse) response;

        System.out.println("필터1");

        if(req.getMethod().equals("POST")){
            String headerAuth = req.getHeader("Authorization");
            // 토큰이 "코스"면 진입할 수 있게
            // 우리는 토큰을 id와 pw 정상적으로 들어와서 로그인이 완료되면 토큰을 만들어주고 클라이언트에게 response해야한다.
            // 요청할 때 마다 header의 Authorization에 value값으로 토큰을 가지고 온다.
            // 근데 토큰이 넘어오면, 이 토큰이 내가 만든 토큰이 맞는지만 검증하면 된다.(RSA, HS256)
            if(headerAuth.equals("cococo")) chain.doFilter(req, res);
            else {
                PrintWriter out = res.getWriter();
                System.out.println("인증안됨");
            }
        }

    }
}
