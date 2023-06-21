package security.example.springsecuritypractice.controller;

import lombok.RequiredArgsConstructor;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.web.bind.annotation.*;
import security.example.springsecuritypractice.model.User;
import security.example.springsecuritypractice.repository.UserRepository;

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
    public String join(@RequestBody User user){
        user.setPassword(bCryptPasswordEncoder.encode(user.getPassword()));;
        user.setRoles("ROLE_USER");
        userRepository.save(user);
        System.out.println(user + "가 회원가입됨");
        return "회원가입완료";
    }

}
