package security.example.springsecuritypractice.controller;

import lombok.RequiredArgsConstructor;
import org.springframework.http.ResponseEntity;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.web.bind.annotation.*;
import security.example.springsecuritypractice.config.auth.PrincipalDetails;
import security.example.springsecuritypractice.model.Member;
import security.example.springsecuritypractice.repository.UserRepository;

import java.security.Security;

@RestController
@RequiredArgsConstructor
public class RestApiController {

    private final UserRepository userRepository;
    private final BCryptPasswordEncoder bCryptPasswordEncoder;

    @GetMapping("home")
    public String home(){
        return"<h1>home</h1>";
    }

    @PostMapping("token")
    public String token(){
        return"<h1>token</h1>";
    }

    @PostMapping("join")
    public String join(@RequestBody Member member){
        member.setPassword(bCryptPasswordEncoder.encode(member.getPassword()));;
        member.setRoles("ROLE_MANAGER");
        userRepository.save(member);
        System.out.println(member + "가 회원가입됨");
        return "회원가입완료";
    }

    // user만 접근 가능
    @GetMapping("api/v1/user")
    public ResponseEntity<?> user(){
        System.out.println("컨트롤러 api/v1/user입니다.");
        try{
            Authentication auth = SecurityContextHolder.getContext().getAuthentication();
            return ResponseEntity.ok().body(auth + "user입니다.");
        }catch (Exception e){
            return ResponseEntity.badRequest().body(e.getMessage());
        }
        /*System.out.println("api/v1/user 컨트롤러에서 불러낸 securitycontextholder의 authentication");
        System.out.println(SecurityContextHolder.getContext().getAuthentication());
        System.out.println("api/v1/user 컨트롤러 파라미터로 들어온 authentication");
        System.out.println(authentication);
        //PrincipalDetails principal = (PrincipalDetails) authentication.getPrincipal();
        System.out.println("principal : " + principal.getMember().getId());
        System.out.println("principal : " + principal.getMember().getUsername());
        System.out.println("principal : " + principal.getMember().getPassword());*/
    }

    // manager, admin 권한만 접근 가능
    @GetMapping("api/v1/manager")
    public String manager(){
        System.out.println("컨트롤러 api/v1/manager입니다.");
        return "<h1>manager</h1>";
    }

    // admin 권한만 접근 가능
    @GetMapping("api/v1/admin")
    public String admin(){
        System.out.println("컨트롤러 api/v1/admin입니다.");
        return "<h1>admin</h1>";
    }

}
