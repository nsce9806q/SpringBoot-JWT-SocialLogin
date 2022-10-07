package study.jwtsociallogin.configuration;

import com.auth0.jwt.JWT;
import com.auth0.jwt.algorithms.Algorithm;
import com.auth0.jwt.exceptions.SignatureVerificationException;
import com.auth0.jwt.exceptions.TokenExpiredException;
import java.io.IOException;
import javax.servlet.FilterChain;
import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.web.authentication.www.BasicAuthenticationFilter;
import study.jwtsociallogin.entity.User;
import study.jwtsociallogin.repository.UserRepository;

public class JwtAuthorizationFilter extends BasicAuthenticationFilter {

  private final UserRepository userRepository;

  public JwtAuthorizationFilter(AuthenticationManager authenticationManager, UserRepository userRepository) {
    super(authenticationManager);
    this.userRepository = userRepository;
  }

  @Override
  protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response,
      FilterChain chain) throws IOException, ServletException {

//    Authorization 헤더에서 토큰 가져오기
    String token = request.getHeader("Authorization");

    if (token == null || !token.startsWith(JwtProperties.TOKEN_PREFIX)) {
      chain.doFilter(request, response);
      return;
    }

    try {
//      JWT 토큰 유효성 검증과 동시에 username을 복호화 한다
      String username = JWT.require(Algorithm.HMAC512(JwtProperties.SECRET)).build()
          .verify(token.replace(JwtProperties.TOKEN_PREFIX, ""))
          .getClaim("username").asString();

      if (username != null) {
//        토큰에서 복호화한 username으로 DB에서 User 조회해서 PrincipalDetails 객체 생성
        User user = userRepository.findByUsername(username);
        PrincipalDetails principalDetails = new PrincipalDetails(user);

//        PrincipalDetails 객체와 권한으로 인증 객체 생성
//        +) 위에서 토큰인증 했으므로 비밀번호 받아서 인증할 필요 없고 권한 처리 목적임
        Authentication authentication = new UsernamePasswordAuthenticationToken(principalDetails,
            null, principalDetails.getAuthorities());

//        시큐리티 세션에 접근하여 강제로 인증 객체 저장
        SecurityContextHolder.getContext().setAuthentication(authentication);

        chain.doFilter(request, response);
      }
    } catch (SignatureVerificationException | TokenExpiredException e) {
      response.setStatus(401);
    } finally {
      response.setStatus(400);
    }
    super.doFilterInternal(request, response, chain);
  }
}
