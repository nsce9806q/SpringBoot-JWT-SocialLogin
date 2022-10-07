package study.jwtsociallogin.configuration;

import lombok.Getter;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.context.annotation.Configuration;
import org.springframework.context.annotation.PropertySource;

@Getter
@PropertySource(value = "classpath:secret.properties")
@Configuration
public class SecretPropertiesConfig {
  @Value("spring.datasource.url")
  private String url;

  @Value("spring.datasource.username")
  private String username;

  @Value("spring.datasource.password")
  private String password;

  @Value("spring.jpa.hibernate.ddl-auto")
  private String ddlAuto;
}
