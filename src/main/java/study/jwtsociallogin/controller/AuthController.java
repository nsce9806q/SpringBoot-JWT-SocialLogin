package study.jwtsociallogin.controller;

import lombok.RequiredArgsConstructor;
import org.springframework.http.ResponseEntity;
import org.springframework.security.core.annotation.AuthenticationPrincipal;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RestController;
import study.jwtsociallogin.configuration.PrincipalDetails;
import study.jwtsociallogin.entity.User;
import study.jwtsociallogin.repository.UserRepository;

@RequiredArgsConstructor
@RestController
public class AuthController {
  private final UserRepository userRepository;

  private final BCryptPasswordEncoder bCryptPasswordEncoder;

  @GetMapping("/")
  public ResponseEntity<String> root(){
    return ResponseEntity.ok().body("hihi");
  }

  @GetMapping("/user")
  public ResponseEntity<User> user(@AuthenticationPrincipal PrincipalDetails user){
    return ResponseEntity.ok().body(user.getUser());
  }

  @PostMapping("/join")
  public ResponseEntity<String> join(@RequestBody User user){
    user.setRole("USER");
    user.setPassword(bCryptPasswordEncoder.encode(user.getPassword()));
    userRepository.save(user);

    return ResponseEntity.ok().body("회원가입완료");
  }

}
