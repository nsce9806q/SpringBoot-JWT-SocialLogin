package study.jwtsociallogin.repository;

import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.stereotype.Repository;
import study.jwtsociallogin.entity.User;

@Repository
public interface UserRepository extends JpaRepository<User, Long> {
  User findByUsername(String username);
}
