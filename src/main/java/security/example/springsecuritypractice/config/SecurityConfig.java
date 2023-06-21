package security.example.springsecuritypractice.config;

import lombok.RequiredArgsConstructor;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.config.annotation.authentication.configuration.AuthenticationConfiguration;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.authentication.www.BasicAuthenticationFilter;
import org.springframework.web.filter.CorsFilter;
import security.example.springsecuritypractice.config.jwt.JwtAuthenticationFilter;
import security.example.springsecuritypractice.filter.MyFilter1;

@EnableWebSecurity
@Configuration
@RequiredArgsConstructor
public class SecurityConfig {

    private final CorsFilter corsFilter;

    @Bean
    public BCryptPasswordEncoder passwordEncoder(){
        return new BCryptPasswordEncoder();
    }

    @Bean
    public AuthenticationManager authenticationManager(AuthenticationConfiguration authConfiguration) throws Exception {
        return authConfiguration.getAuthenticationManager();
    }

    @Bean
    public SecurityFilterChain filterChain(HttpSecurity http) throws Exception{
        http.addFilterBefore(new MyFilter1(), BasicAuthenticationFilter.class);
        //AuthenticationManager authenticationManager = http.getSharedObject(AuthenticationManager.class);
        http.csrf().disable();
        http.sessionManagement().sessionCreationPolicy(SessionCreationPolicy.STATELESS)
                .and()
                .addFilter(corsFilter)
                .formLogin().disable()
                .httpBasic().disable()
                .addFilter(new JwtAuthenticationFilter()) // AuthenticationManager을 통해 로그인한다. jwt필터가 상속 받은 필터는 원래
                .authorizeHttpRequests()
                .requestMatchers("api/v1/user/**")
                .hasAnyRole("USER", "MANAGER", "ADMIN")
                .requestMatchers("api/v1/manager/**")
                .hasRole("MANAGER")
                .requestMatchers("api/v1/admin/**")
                .hasRole("ADMIN")
                .anyRequest().permitAll();
        return http.build();
    }
}
