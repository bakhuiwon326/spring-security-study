package security.example.springsecuritypractice.config.jwt;

import com.auth0.jwt.JWT;
import com.auth0.jwt.algorithms.Algorithm;
import com.fasterxml.jackson.databind.ObjectMapper;
import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import lombok.RequiredArgsConstructor;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.annotation.Bean;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.config.annotation.authentication.configuration.AuthenticationConfiguration;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;
import security.example.springsecuritypractice.config.auth.PrincipalDetails;
import security.example.springsecuritypractice.model.Member;

import java.io.IOException;
import java.util.Date;

// /login 요청해서 username, password로 전송하면(post)
// UsernamePasswordAuthenticationFilter 가 실행된다.
// 단, formlogin이 활성화 된 상태에서. 만약 formlogin을 disable했는데 사용하고 싶다면?
// UsernamePasswordAuthenticationFilter를 상속한 이 클래스 필터를 addFilter해준다.

@RequiredArgsConstructor
public class JwtAuthenticationFilter extends UsernamePasswordAuthenticationFilter {
    // 원래 UsernamePasswordAuthenticationFilter는 /login 호출 때 실행되는 필터임.
    // forLogin()을 disable했기 때문에 실행안됨.

    private final AuthenticationManager authenticationManager;

    // /login 요청을 하면, 로그인 시도를 위해서 실행되는 함수 - authenticationManager에 의해 실행된다.
    @Override
    public Authentication attemptAuthentication(HttpServletRequest request, HttpServletResponse response) throws AuthenticationException {
        System.out.println("JwtAuthenticationFilter: 로그인 시도중");

        // 1.request에 담긴 username,password를 받아서
        try {
            // json 형태로 request들어온거에서 username과 password 추출
            ObjectMapper objectMapper = new ObjectMapper();
            Member member = objectMapper.readValue(request.getInputStream(), Member.class);
            System.out.println("json형태로 들어온 member" + member);

            // user의 로그인할때 사용한 username과 password를 이용해 토큰을 하나 만든다.
            UsernamePasswordAuthenticationToken authenticationToken = new UsernamePasswordAuthenticationToken(member.getUsername(), member.getPassword());

            System.out.println("authenticationToken: " + authenticationToken);
            System.out.println("authenticationManager: " + authenticationManager);
            // principalDetailService의 loadUserByUsernam() 함수가 실행된다.
            // authentication에 사용자의 로그인 정보가 저장된다.
            // DB에 있는 username과 password가 일치한다.는 의미.
            Authentication authentication = authenticationManager.authenticate(authenticationToken);

            // authentication객체가 session 영역에 저장되었다. => 로그인 되었다는 의미
            PrincipalDetails principalDetails = (PrincipalDetails) authentication.getPrincipal();
            System.out.println("로그인 완료됨:" + principalDetails.getMember().getUsername());

            return authentication;
        } catch (IOException e) {
            e.printStackTrace();
        }

        // 2.정상인지 로그인 시도를 해본다.
        // authenticationManager로 로그인시도를 하면, PrincipalDetailService의 loadUserByUsername()이 실행된다.

        // 3.Princialdetails를 세션에 담고(세션에 담아야 security가 권한 관리를 해준다.)

        // 4.JWT토큰을 만들어서 응답해 준다.

        return null;
    }


    // attempAuthentication 실행 후 인증이 정상적으로 되었으면 아래 함수가 실행된다.
    // 여기서 jwt 토큰을 만들어서 reqeust 요청한 사용자에게 jwt토큰을 response하면 된다.
    @Override
    protected void successfulAuthentication(HttpServletRequest request, HttpServletResponse response, FilterChain chain, Authentication authResult) throws IOException, ServletException {
        System.out.println("successfulAuthentication 실행됨: 인증이 완료되었다는 뜻");
        PrincipalDetails principalDetails = (PrincipalDetails) authResult.getPrincipal();
        System.out.println("successfulAuthentication에서 가져온 principal details");
        System.out.println(principalDetails);
        // Hash암호 방식.
        String jwtToken = JWT.create()
                .withSubject(principalDetails.getUsername())
                .withExpiresAt(new Date(System.currentTimeMillis() + (60000*10)))
                .withClaim("id", principalDetails.getMember().getId())
                .withClaim("username", principalDetails.getMember().getUsername())
                .sign(Algorithm.HMAC512("secretKey"));
        response.addHeader("Authorization", "Bearer " + jwtToken);
        System.out.println("토큰 발급");
        // jwt토큰 사용하면, 세션을 만들 이유가 딱히 없지만. 단지 권한 처리때문에 session을 사용한다.
    }
}
