package security.example.springsecuritypractice.config.jwt;

import com.auth0.jwt.JWT;
import com.auth0.jwt.algorithms.Algorithm;
import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.web.authentication.www.BasicAuthenticationFilter;
import security.example.springsecuritypractice.config.auth.PrincipalDetails;
import security.example.springsecuritypractice.model.Member;
import security.example.springsecuritypractice.repository.UserRepository;

import java.io.IOException;

// security가 filter를 가지고 있는데 그 필터 중에 BasicAuthenticationFilter라는 것이 있다.
// 권한이나 인증이 필요한 특정 주소를 요청했ㅇ르 때 위 필터를 무조건 타게 되어있다.
// 만약 권한이 인증이 필요한 주소가 아니라면 이 필터를 안탄다.
public class JwtAuthorizationFilter extends BasicAuthenticationFilter {
    private UserRepository userRepository;
    public JwtAuthorizationFilter(AuthenticationManager authenticationManager, UserRepository userRepository) {
        super(authenticationManager);
        this.userRepository = userRepository;
    }

    // 인증이나 권한이 필요한 주소요청이 있을 때 해당 필터를 타게 될 것이다.
    @Override
    protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response, FilterChain chain) throws IOException, ServletException {
        System.out.println("인증이나 권한이 필요한 주소 요청이 됨.");
        String jwtHeader = request.getHeader("Authorization");
        System.out.println("jwtHeader:" + jwtHeader);

        // header가 있는지 확인한다.
        if(jwtHeader == null || !jwtHeader.startsWith("Bearer")){
            chain.doFilter(request, response);
            return;
        }
        // Jwt 토큰을 검증해서 정상적인 사용자인지 확인한다.
        String jwtToken = request.getHeader("Authorization").replace("Bearer ",""); // "Bearer "를 공백""으로 치환한다.
        String username = JWT.require(Algorithm.HMAC512("secretKey")).build().verify(jwtToken).getClaim("username").asString(); // verfiy: 서명하는거

        // 서명이 정상적으로 되었다면
        if(username != null){
            System.out.println("서명이 정상적으로 되었습니다.");
            Member memberEntity = userRepository.findByUsername(username);
            PrincipalDetails princialDetails = new PrincipalDetails(memberEntity);
            // jwt 토큰 서명을 통해서 서명이 정상이면 authentication 객체를 만들어 준다. -> 서명을 통해 username이 있으면 authentication을 만들어 준다.
            Authentication authentication = new UsernamePasswordAuthenticationToken(princialDetails, null, princialDetails.getAuthorities());
            System.out.println("-- authentication: " + authentication);
            // 강제로 시큐리티의 세션에 접근하여 authentication 객체를 저장한다.
            SecurityContextHolder.getContext().setAuthentication(authentication);
            System.out.println("doFilterInternal에서 securitycontextholder에 저장된 auth:");
            System.out.println(SecurityContextHolder.getContext().getAuthentication());
            chain.doFilter(request, response);
        }
    }
}
