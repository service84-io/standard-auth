package io.service84.library.standardauth.api.rest.authentication;

import java.net.MalformedURLException;
import java.net.URISyntaxException;

import org.springframework.beans.factory.annotation.Value;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;

@Configuration("629F6DDC-F62F-41CC-B8D4-86825A10C9FE")
public class Service84JWTAFConfigurer {
  @Value("${io.service84.library.standardauth.jwtaf.url:#{null}}")
  private String url;

  @Value("${io.service84.library.standardauth.jwtaf.authority:#{null}}")
  private String authority;

  @Value("${io.service84.library.standardauth.jwtaf.defaultPublicKeyTTL:86400}")
  private Integer defaultPublicKeyTTL;

  @Value("${io.service84.library.standardauth.jwtaf.minSecondsRemaining:6}")
  private Integer minSecondsRemaining;

  @Bean("3066D1E1-C0F3-4200-A898-B4F0C6373B60")
  public Service84JWTAuthenticationFilter getService84JWTAuthenticationFilter() {
    System.out.println("Hi Tyler");
    System.out.println(url);
    if (url == null) {
      return null;
    } else {
      try {
        return new Service84JWTAuthenticationFilter(
            url, authority, defaultPublicKeyTTL, minSecondsRemaining);
      } catch (URISyntaxException | MalformedURLException e) {
        throw new Error(e);
      }
    }
  }
}
