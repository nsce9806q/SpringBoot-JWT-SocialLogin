package study.jwtsociallogin.configuration;

import com.auth0.jwt.JWT;
import com.auth0.jwt.algorithms.Algorithm;
import com.fasterxml.jackson.databind.ObjectMapper;
import java.io.IOException;
import java.util.Date;
import javax.servlet.FilterChain;
import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import lombok.RequiredArgsConstructor;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;
import study.jwtsociallogin.entity.User;
import study.jwtsociallogin.repository.UserRepository;

@RequiredArgsConstructor
public class JwtAuthenticationFilter extends UsernamePasswordAuthenticationFilter {

  private final AuthenticationManager authenticationManager;
  private final UserRepository userRepository;

  private User requestUser = null;

  @Override
  public Authentication attemptAuthentication
      (HttpServletRequest request, HttpServletResponse response) throws AuthenticationException {

    try {
//      Request Body에서 아이디/비밀번호 가져와서 유저 객체에 넣어준다
      ObjectMapper om = new ObjectMapper();
      requestUser = om.readValue(request.getInputStream(), User.class);

//      위 유저 객체로 인증 토큰 생성
      UsernamePasswordAuthenticationToken authenticationToken = new UsernamePasswordAuthenticationToken(requestUser.getUsername(), requestUser.getPassword());

//      authenticate 함수가 호출되면
//      1. AuthenticationProvider가 PrincipalDetailsService의 loadUserByUsername를 호출해서 UserDetails를 리턴 받는다.
//      2. UserDetails(DB)의 Password와 Credential를 비교해서 비밀번호 비교
//      3-1. 성공시 successfulAuthentication 호출
//      3-2. 실패시 unsuccessfulAuthentication 호출
//      4. authentication 객체 생성해서 필터 체인으로 리턴
      return authenticationManager.authenticate(authenticationToken);

    } catch (IOException e) {
      e.printStackTrace();
    }

    return null;
  }

  @Override
  protected void successfulAuthentication(HttpServletRequest request, HttpServletResponse response,
      FilterChain chain, Authentication authResult) throws IOException, ServletException {

//    인증 결과에서 유저 정보 가져오기
    PrincipalDetails principalDetails = (PrincipalDetails) authResult.getPrincipal();

//    AccessToken, RefreshToken 생성
    String accessToken = createJwtToken("access_token", principalDetails);
    String refreshToken = createJwtToken("refresh_token", principalDetails);

//    RefreshToken DB 저장 -> 추후 redis 대체
    principalDetails.getUser().setRefreshToken(refreshToken);
    userRepository.save(principalDetails.getUser());

//    Response 객체 헤더/바디 설정
    response.setContentType("application/json");
    response.setCharacterEncoding("UTF-8");
    response.getWriter()
        .write("\"access_token\":" + JwtProperties.TOKEN_PREFIX + accessToken + ","
        + "\"refresh_token\":" + JwtProperties.TOKEN_PREFIX + refreshToken);

  }

  @Override
  protected void unsuccessfulAuthentication(HttpServletRequest request, HttpServletResponse response,
      AuthenticationException failed) throws IOException, ServletException {

    User user = userRepository.findByUsername(requestUser.getUsername());

//    아이디로 유저 조회가 안될 경우
    if(user == null) {
      response.setStatus(401);
      response.setContentType("application/json");
      response.setCharacterEncoding("UTF-8");
      response.getWriter()
          .write("\"error\": UsernamePasswordFailureException");

      return;
    }

//    비밀번호가 틀렸을 경우
    response.setStatus(401);
    response.setContentType("application/json");
    response.setCharacterEncoding("UTF-8");
    response.getWriter()
        .write("\"error\": UsernamePasswordFailureException");

  }

  public String createJwtToken(String tokenName, PrincipalDetails principalDetails) {
    return JWT.create()
        .withSubject(tokenName)
        .withExpiresAt(new Date(System.currentTimeMillis()+JwtProperties.REFRESH_TOKEN_EXPIRATION_TIME))
        .withClaim("username", principalDetails.getUsername())
        .sign(Algorithm.HMAC512(JwtProperties.SECRET));
  }
}
