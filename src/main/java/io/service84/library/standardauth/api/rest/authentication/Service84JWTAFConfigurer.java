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
