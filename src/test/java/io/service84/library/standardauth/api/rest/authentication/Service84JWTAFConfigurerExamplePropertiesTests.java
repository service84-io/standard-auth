package io.service84.library.standardauth.api.rest.authentication;

import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.mockito.Mockito.mock;

import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.TestConfiguration;
import org.springframework.context.annotation.Bean;
import org.springframework.test.context.TestPropertySource;
import org.springframework.test.context.junit.jupiter.SpringExtension;

import io.service84.library.authutils.services.AuthenticationService;
import io.service84.library.standardauth.services.KeyProviderService;

@ExtendWith(SpringExtension.class)
@TestPropertySource(properties = {"io.service84.library.standardauth.jwtaf.url=example.com"})
public class Service84JWTAFConfigurerExamplePropertiesTests {
  @TestConfiguration
  public static class Configuration {
    @Bean
    public AuthenticationService getAuthenticationService() {
      return new AuthenticationService();
    }

    @Bean
    public KeyProviderService getKeyProviderService() {
      return mock(KeyProviderService.class);
    }
  }

  @TestConfiguration
  public static class TestService84JWTAFConfigurer extends Service84JWTAFConfigurer {}

  // Test Subject
  @Autowired private Service84JWTAFConfigurer service84JWTAFConfigurer;

  @Autowired private Service84JWTAuthenticationFilter service84JWTAuthenticationFilter;
  @Autowired private AuthenticationService authenticationService;
  @Autowired private KeyProviderService mockKeyProviderService;

  @Test
  public void existenceTest() {
    assertNotNull(service84JWTAFConfigurer);
    assertNotNull(service84JWTAuthenticationFilter);
    assertNotNull(authenticationService);
    assertNotNull(mockKeyProviderService);
  }
}
