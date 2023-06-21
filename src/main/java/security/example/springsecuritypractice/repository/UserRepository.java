package security.example.springsecuritypractice.repository;

import org.springframework.data.jpa.repository.JpaRepository;
import security.example.springsecuritypractice.model.User;

public interface UserRepository extends JpaRepository<User, Long> {
    User findByUsername(String username);
}
