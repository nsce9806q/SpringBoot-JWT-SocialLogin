# SpringBoot + JWT + SocialLogin
## Goals
- Spring Security 5.7 부터 Deprecated된 WebSecurityConfigurerAdapter 대신 SecurityFilterChain을 Bean 등록하여 대체하기
- JWT (accessToken, refreshToken) 사용하여 구현
- 네이버 로그인 연동
- 카카오 로그인 연동
* * *
## How it works
1. SecurityConfig에 SecurityFilterChain를 Bean 등록한다.
2. 커스텀 필터(CustomDSL)에 CorsFilter와 인증(JwtAuthenticationFilter), 인가(JwtAuthorizationFilter) 필터를 적용한다.
3. SecurityFilterChain에 커스텀 필터, 접근 권한 필터 등을 적용한다.
### 기본 로그인
#### 인증 로직
1. "/login"으로 http 요청이 들어오면 SecurityFilterChain에서 JwtAuthenticationFilter가 요청을 낚아 챈다.
2. JwtAuthenticationFilter의 attemptAuthentication 함수 호출
   1. 요청 body에서 아이디/비밀번호를 가져온다.
   2. 아이디/비밀번호로 인증 토큰 생성
   3. AuthenticationManager의 authenticate 함수에 인증 토큰 인자로 넣어서 호출
      1. AuthenticationProvider가 PrincipalDetailsService의 loadUserByUsername를 호출해서 UserDetails를 리턴 받는다. 
      2. UserDetails(DB)의 Password와 Credential를 비교해서 비밀번호 비교 
      3. 성공시 successfulAuthentication 호출 (실패하면 unsuccessfulAuthentication 호출)
         1. 인증 결과에서 유저 정보 가져온다
         2. AccessToken/RefreshToken 생성
         3. RefreshToken을 DB에 저장
         4. Response body에 AccessToken/RefreshToken를 담는다.
      4. authentication 객체 생성해서 필터 체인으로 리턴
3. 발급된 토큰을 response 한다.
#### 인가 로직
1. 접근 권한 필터에서 인가가 필요하면 request를 JwtAuthorizationFilter가 낚아 챈다.
2. JwtAuthorizationFilter에서 doFilterInternal 함수를 호출한다
   1. Authorization 헤더에서 토큰 가져오기
   2. 토큰 유효성 검증하고 username을 복호화한다.
   3. 토큰에서 복호화한 username으로 User 조회해서 PrincipalDetails 객체 생성
   4. PrincipalDetails 객체와 권한으로 인증 객체 생성
   5. 시큐리티 세션에 접근하여 강제로 인증 객체 저장
3. 다음 체인 필터로 넘겨서 api 접근하게 한다.
#### SecurityConfig.java

```java
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
```

#### User.java
```java
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
```

#### UserRepository.java
```java
@Repository
public interface UserRepository extends JpaRepository<User, Long> {
  User findByUsername(String username);
}
```

#### PrincipalDetails.java
```java
@Data
@RequiredArgsConstructor
public class PrincipalDetails implements UserDetails {

  private User user;

  public PrincipalDetails(User user){
    this.user = user;
  }

  @Override
  public Collection<? extends GrantedAuthority> getAuthorities() {
    Collection<GrantedAuthority> authorities = new ArrayList<>();
    user.roles().forEach((role) -> authorities.add(() -> role));
    return authorities;
  }

  @Override
  public String getPassword() {
    return user.getPassword();
  }

  @Override
  public String getUsername() {
    return user.getUsername();
  }

  @Override
  public boolean isAccountNonExpired() {
    return true;
  }

  @Override
  public boolean isAccountNonLocked() {
    return true;
  }

  @Override
  public boolean isCredentialsNonExpired() {
    return true;
  }

  @Override
  public boolean isEnabled() {
    return true;
  }

}
```

#### PrincipalDetailsService.java
```java
@RequiredArgsConstructor
@Service
public class PrincipalDetailsService implements UserDetailsService {

  private final UserRepository userRepository;

  @Override
  public UserDetails loadUserByUsername(String username) throws UsernameNotFoundException {
    User user = userRepository.findByUsername(username);
    return new PrincipalDetails(user);
  }
}
```

#### CorsConfig.java
```java
@Configuration
public class CorsConfig {

  @Bean
  public CorsFilter corsFilter(){
    UrlBasedCorsConfigurationSource source = new UrlBasedCorsConfigurationSource();
    CorsConfiguration config = new CorsConfiguration();

    config.setAllowCredentials(true); // 서버에서 응답 한 json을 자바스크립트에서 처리할 수 있게 설정
    config.addAllowedOriginPattern("*"); // 모든 ip의 응답을 허용, allowcredentials=true 사용시 allowedorigin("*") 사용금지, allowedoriginpattern 사용 (https://kim6394.tistory.com/273)
    config.addAllowedHeader("*"); // 모든 헤더의 응답을 허용
    config.addAllowedMethod("*"); // POST GET PUT DELETE 등 모든 http 메소드 허용

    source.registerCorsConfiguration("/**", config); // 모든 url에 대해 위 config 적용
    return new CorsFilter(source);
  }
}
```

#### JwtAuthenticationFilter.java
```java
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
```

#### JwtAuthorization.java
```java
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
```
* * *
## Env
- Spring Boot 2.7.4
- Spring Security 5.7.3
- JDK 17
- Gradle
- MySQL 8.0.28
### Dependency
```
implementation 'org.springframework.boot:spring-boot-starter-data-jpa'
implementation 'org.springframework.boot:spring-boot-starter-oauth2-client'
implementation 'org.springframework.boot:spring-boot-starter-security'
implementation 'org.springframework.boot:spring-boot-starter-web'
implementation group: 'com.auth0', name: 'java-jwt', version: '4.0.0'
compileOnly 'org.projectlombok:lombok'
runtimeOnly 'mysql:mysql-connector-java'
```
src/main/resources/secret.properties.java 생성
```
spring.datasource.url = jdbc:mysql://${{MYSQL_URL}}/${{MYSQL_SCHEMA}}?autoReconnect=true
spring.datasource.username = ${{MYSQL_USERNAME}}
spring.datasource.password = ${{MYSQL_PASSWORD}}
spring.jpa.hibernate.ddl-auto = DDL-MODE(ex. CREATE, VALIDATE)
```