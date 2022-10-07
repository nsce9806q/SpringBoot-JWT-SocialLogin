package study.jwtsociallogin.entity;

import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;
import javax.persistence.Column;
import javax.persistence.Entity;
import javax.persistence.GeneratedValue;
import javax.persistence.GenerationType;
import javax.persistence.Id;
import lombok.Data;

@Data
@Entity
public class User {

  @Id
  @GeneratedValue(strategy = GenerationType.IDENTITY)
  private long id;

  private String username;

  private String password;

  private String role;

  @Column(nullable = true)
  private String refreshToken;

  public List<String> roles() {
    if(role.length() > 0){
      return Arrays.asList(role.split(","));
    }
    return new ArrayList<>();
  }
}
