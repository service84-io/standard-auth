package io.service84.library.standardauth.api.rest.authentication;

import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertNull;

import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.TestConfiguration;
import org.springframework.test.context.junit.jupiter.SpringExtension;

@ExtendWith(SpringExtension.class)
public class Service84JWTAFConfigurerNoPropertiesTests {
  @TestConfiguration
  public static class TestService84JWTAFConfigurer extends Service84JWTAFConfigurer {}

  // Test Subject
  @Autowired private Service84JWTAFConfigurer service84JWTAFConfigurer;

  @Autowired(required = false)
  private Service84JWTAuthenticationFilter service84JWTAuthenticationFilter;

  @Test
  public void existenceTest() {
    assertNotNull(service84JWTAFConfigurer);
    assertNull(service84JWTAuthenticationFilter);
  }
}
