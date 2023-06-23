package security.example.springsecuritypractice.config.auth;

import lombok.RequiredArgsConstructor;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.stereotype.Service;
import security.example.springsecuritypractice.model.Member;
import security.example.springsecuritypractice.repository.UserRepository;

@Service
@RequiredArgsConstructor
public class PrincipleDetailService implements UserDetailsService {

    private final UserRepository userRepository;

    @Override
    public UserDetails loadUserByUsername(String username) throws UsernameNotFoundException {
        System.out.println("PrincipleDetailService의 loadUserByUsername()");
        Member memberEntity = userRepository.findByUsername(username);
        System.out.println("MemberEntity: " + memberEntity);
        return new PrincipalDetails(memberEntity);
    }
}
