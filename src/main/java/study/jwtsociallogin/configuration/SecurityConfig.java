package study.jwtsociallogin.configuration;

import lombok.RequiredArgsConstructor;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configurers.AbstractHttpConfigurer;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.core.Authentication;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.web.filter.CorsFilter;
import study.jwtsociallogin.repository.UserRepository;

@RequiredArgsConstructor
@EnableWebSecurity
@Configuration
public class SecurityConfig {

    private final CorsFilter corsFilter;
    private final UserRepository userRepository;

    @Bean
    public SecurityFilterChain filterChain(HttpSecurity http) throws Exception {
      http
          .csrf().disable() // 쿠키 or 세션을 사용하지 않으므로 disable
          .sessionManagement().sessionCreationPolicy(SessionCreationPolicy.STATELESS); // 세션을 stateless

      http
          .formLogin().disable() // formLogin 안써요
          .httpBasic().disable(); // httpBasic: id/pw를 base64로 인코딩해서 authorization 헤더에 넣어서 http 통신

      http.apply(new CustomDsl()); //커스텀한 필터(corsFilter, 인증/인가 필터) 등록

      // URL과 ROLE에 따른 API 접근 권한 부여
      http.authorizeRequests()
          .antMatchers("/user").hasRole("USER")
          .anyRequest().permitAll();

      return http.build();
    }

    public class CustomDsl extends AbstractHttpConfigurer<CustomDsl, HttpSecurity> {


      @Override
      public void configure(HttpSecurity http) throws Exception {
        AuthenticationManager authenticationManager = http.getSharedObject(AuthenticationManager.class);

        http
            .addFilter(corsFilter)
            .addFilter(new JwtAuthenticationFilter(authenticationManager, userRepository))
            .addFilter(new JwtAuthorizationFilter(authenticationManager, userRepository));
      }
    }

    @Bean
    public BCryptPasswordEncoder encodePassword(){
      return new BCryptPasswordEncoder();
    }
}
