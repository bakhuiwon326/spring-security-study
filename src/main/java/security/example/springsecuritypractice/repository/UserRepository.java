package security.example.springsecuritypractice.repository;

import org.springframework.data.jpa.repository.JpaRepository;
import security.example.springsecuritypractice.model.Member;

public interface UserRepository extends JpaRepository<Member, Long> {
    Member findByUsername(String username);
}
