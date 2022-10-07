package study.jwtsociallogin.configuration;

public interface JwtProperties {
  String SECRET = "LSY IS LEGEND";
  int REFRESH_TOKEN_EXPIRATION_TIME = 604800000; // 7일
  int ACCESS_TOKEN_EXPIRATION_TIME = 1800000; // 30분
  String TOKEN_PREFIX = "Bearer ";
}