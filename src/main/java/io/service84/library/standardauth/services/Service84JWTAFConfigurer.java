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

package io.service84.library.standardauth.services;

import java.net.MalformedURLException;
import java.net.URISyntaxException;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;

@Configuration("0D79667F-0FEA-4699-B648-7EEE00676313")
public class Service84JWTAFConfigurer {
  private static final Logger logger = LoggerFactory.getLogger(Service84JWTAFConfigurer.class);

  @Value("${io.service84.library.standardauth.jwtaf.url:#{null}}")
  private String url;

  @Value("${io.service84.library.standardauth.jwtaf.issuer:#{null}}")
  private String issuer;

  @Value("${io.service84.library.standardauth.jwtaf.authority:#{null}}")
  private String authority;

  @Value("${io.service84.library.standardauth.jwtaf.defaultPublicKeyTTL:86400}")
  private Integer defaultPublicKeyTTL;

  @Value("${io.service84.library.standardauth.jwtaf.minSecondsRemaining:6}")
  private Integer minSecondsRemaining;

  @Bean("03B64610-16DF-4721-8A62-8FB614C1C357")
  public Service84JWTAuthenticationFilter getService84JWTAuthenticationFilter() {
    logger.debug("getService84JWTAuthenticationFilter");
    if (url == null) {
      return null;
    }

    try {
      return new Service84JWTAuthenticationFilter(
          url, issuer, authority, defaultPublicKeyTTL, minSecondsRemaining);
    } catch (URISyntaxException | MalformedURLException e) {
      throw new Error(e);
    }
  }
}
