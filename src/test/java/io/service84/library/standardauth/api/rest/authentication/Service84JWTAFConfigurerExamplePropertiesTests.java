/*
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

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
