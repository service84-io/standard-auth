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

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.reset;
import static org.mockito.Mockito.when;

import java.io.IOException;
import java.net.MalformedURLException;
import java.net.URISyntaxException;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.NoSuchAlgorithmException;
import java.security.interfaces.RSAPrivateKey;
import java.security.interfaces.RSAPublicKey;
import java.time.ZonedDateTime;
import java.util.ArrayList;
import java.util.Date;
import java.util.List;
import java.util.UUID;

import javax.servlet.DispatcherType;
import javax.servlet.FilterChain;
import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.Mockito;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Qualifier;
import org.springframework.boot.test.context.TestConfiguration;
import org.springframework.context.annotation.Bean;
import org.springframework.test.context.junit.jupiter.SpringExtension;

import com.auth0.jwt.JWT;
import com.auth0.jwt.algorithms.Algorithm;
import com.auth0.jwt.interfaces.RSAKeyProvider;

import io.service84.library.authutils.services.AuthenticationService;

@ExtendWith(SpringExtension.class)
public class Service84JWTAuthenticationFilterWithAuthorityTests {
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

    @Bean("9C7B20C5-91F5-4D08-B929-C7EB7E45612D")
    public RSAKeyProvider getRSAKeyProvider9C7B20C5() throws NoSuchAlgorithmException {
      KeyPairGenerator keyGen;
      keyGen = KeyPairGenerator.getInstance("RSA");
      keyGen.initialize(4096);
      KeyPair keyPair = keyGen.genKeyPair();
      RSAPrivateKey rsaPrivateKey = (RSAPrivateKey) keyPair.getPrivate();
      RSAPublicKey rsaPublicKey = (RSAPublicKey) keyPair.getPublic();
      KeyProviderService tempKPService = new KeyProviderService();
      return tempKPService.wrapKeys(rsaPrivateKey, rsaPublicKey);
    }

    @Bean("E5BDC68F-07C3-4D17-B96D-6F158DF78404")
    public RSAKeyProvider getRSAKeyProviderE5BDC68F() throws NoSuchAlgorithmException {
      KeyPairGenerator keyGen;
      keyGen = KeyPairGenerator.getInstance("RSA");
      keyGen.initialize(4096);
      KeyPair keyPair = keyGen.genKeyPair();
      RSAPrivateKey rsaPrivateKey = (RSAPrivateKey) keyPair.getPrivate();
      RSAPublicKey rsaPublicKey = (RSAPublicKey) keyPair.getPublic();
      KeyProviderService tempKPService = new KeyProviderService();
      return tempKPService.wrapKeys(rsaPrivateKey, rsaPublicKey);
    }

    @Bean
    public Service84JWTAuthenticationFilter getService84JWTAuthenticationFilter()
        throws MalformedURLException, URISyntaxException {
      return new Service84JWTAuthenticationFilter(
          "https://example.com", "ExampleAuthority", null, null);
    }
  }

  private static String AuthenticationHeader = "Authentication";
  private static String BearerPrefix = "Bearer ";

  // Test Subject
  @Autowired private Service84JWTAuthenticationFilter service84JWTAuthenticationFilter;

  @Autowired private AuthenticationService authenticationService;
  @Autowired private KeyProviderService mockKeyProviderService;

  @Autowired
  @Qualifier("9C7B20C5-91F5-4D08-B929-C7EB7E45612D")
  private RSAKeyProvider rsaKeyProviderFilter;

  @Autowired
  @Qualifier("E5BDC68F-07C3-4D17-B96D-6F158DF78404")
  private RSAKeyProvider rsaKeyProviderNotFilter;

  @Test
  public void existenceTest() {
    assertNotNull(service84JWTAuthenticationFilter);
    assertNotNull(authenticationService);
    assertNotNull(mockKeyProviderService);
    assertNotNull(rsaKeyProviderFilter);
    assertNotNull(rsaKeyProviderNotFilter);
  }

  private String makeNotFilterToken(
      String subject, List<String> scopes, String issuer, Integer durationSeconds) {
    Date expiration = Date.from(ZonedDateTime.now().plusSeconds(durationSeconds).toInstant());
    Algorithm algorithm = Algorithm.RSA256(rsaKeyProviderNotFilter);
    return BearerPrefix
        + JWT.create()
            .withIssuer(issuer)
            .withExpiresAt(expiration)
            .withSubject(subject.toString())
            .withClaim("scope", String.join(" ", scopes))
            .sign(algorithm);
  }

  private String makeRSA256FilterToken(
      String subject, List<String> scopes, String issuer, Integer durationSeconds) {
    Date expiration = Date.from(ZonedDateTime.now().plusSeconds(durationSeconds).toInstant());
    Algorithm algorithm = Algorithm.RSA256(rsaKeyProviderFilter);
    return BearerPrefix
        + JWT.create()
            .withIssuer(issuer)
            .withExpiresAt(expiration)
            .withSubject(subject.toString())
            .withClaim("scope", String.join(" ", scopes))
            .sign(algorithm);
  }

  private String makeRSA512FilterToken(
      String subject, List<String> scopes, String issuer, Integer durationSeconds) {
    Date expiration = Date.from(ZonedDateTime.now().plusSeconds(durationSeconds).toInstant());
    Algorithm algorithm = Algorithm.RSA512(rsaKeyProviderFilter);
    return BearerPrefix
        + JWT.create()
            .withIssuer(issuer)
            .withExpiresAt(expiration)
            .withSubject(subject.toString())
            .withClaim("scope", String.join(" ", scopes))
            .sign(algorithm);
  }

  private String makeUnpermittedToken(
      String subject, List<String> scopes, String issuer, Integer durationSeconds) {
    Date expiration = Date.from(ZonedDateTime.now().plusSeconds(durationSeconds).toInstant());
    Algorithm algorithm = Algorithm.none();
    return BearerPrefix
        + JWT.create()
            .withIssuer(issuer)
            .withExpiresAt(expiration)
            .withSubject(subject.toString())
            .withClaim("scope", String.join(" ", scopes))
            .sign(algorithm);
  }

  @Test
  public void rsa512TokenCheck() throws ServletException, IOException {
    String issuer = "example.com";
    String subject = UUID.randomUUID().toString();
    String scopeA = UUID.randomUUID().toString();
    String scopeB = UUID.randomUUID().toString();
    List<String> scopes = new ArrayList<>();
    scopes.add(scopeA);
    scopes.add(scopeB);
    Integer durationSeconds = 86400;
    String token = makeRSA512FilterToken(subject, scopes, issuer, durationSeconds);
    HttpServletRequest mockRequest = mock(HttpServletRequest.class);
    HttpServletResponse mockResponse = mock(HttpServletResponse.class);
    FilterChain mockChain = mock(FilterChain.class);
    when(mockRequest.getHeader(Mockito.eq(AuthenticationHeader))).thenReturn(token);
    when(mockRequest.getDispatcherType()).thenReturn(DispatcherType.REQUEST);
    service84JWTAuthenticationFilter.doFilter(mockRequest, mockResponse, mockChain);
    assertEquals(subject, authenticationService.getSubject());
    assertEquals(3, authenticationService.getScopes().size());
    assertTrue(authenticationService.getScopes().contains(scopeA));
    assertTrue(authenticationService.getScopes().contains(scopeB));
    assertTrue(authenticationService.getScopes().contains("ExampleAuthority"));
  }

  @BeforeEach
  public void setup() {
    reset(mockKeyProviderService);
    when(mockKeyProviderService.wrapJWKProvider(any())).thenReturn(rsaKeyProviderFilter);
    authenticationService.setAuthentication(null);
  }

  @Test
  public void unpermittedAlgorithmCheck() throws ServletException, IOException {
    String issuer = "not.example.com";
    String subject = UUID.randomUUID().toString();
    String scopeA = UUID.randomUUID().toString();
    String scopeB = UUID.randomUUID().toString();
    List<String> scopes = new ArrayList<>();
    scopes.add(scopeA);
    scopes.add(scopeB);
    Integer durationSeconds = 86400;
    String token = makeUnpermittedToken(subject, scopes, issuer, durationSeconds);
    HttpServletRequest mockRequest = mock(HttpServletRequest.class);
    HttpServletResponse mockResponse = mock(HttpServletResponse.class);
    FilterChain mockChain = mock(FilterChain.class);
    when(mockRequest.getHeader(Mockito.eq(AuthenticationHeader))).thenReturn(token);
    when(mockRequest.getDispatcherType()).thenReturn(DispatcherType.REQUEST);
    service84JWTAuthenticationFilter.doFilter(mockRequest, mockResponse, mockChain);
    Assertions.assertNull(authenticationService.getSubject());
    assertTrue(authenticationService.getScopes().isEmpty());
  }

  @Test
  public void validTokenCheck() throws ServletException, IOException {
    String issuer = "example.com";
    String subject = UUID.randomUUID().toString();
    String scopeA = UUID.randomUUID().toString();
    String scopeB = UUID.randomUUID().toString();
    List<String> scopes = new ArrayList<>();
    scopes.add(scopeA);
    scopes.add(scopeB);
    Integer durationSeconds = 86400;
    String token = makeRSA256FilterToken(subject, scopes, issuer, durationSeconds);
    HttpServletRequest mockRequest = mock(HttpServletRequest.class);
    HttpServletResponse mockResponse = mock(HttpServletResponse.class);
    FilterChain mockChain = mock(FilterChain.class);
    when(mockRequest.getHeader(Mockito.eq(AuthenticationHeader))).thenReturn(token);
    when(mockRequest.getDispatcherType()).thenReturn(DispatcherType.REQUEST);
    service84JWTAuthenticationFilter.doFilter(mockRequest, mockResponse, mockChain);
    assertEquals(subject, authenticationService.getSubject());
    assertEquals(3, authenticationService.getScopes().size());
    assertTrue(authenticationService.getScopes().contains(scopeA));
    assertTrue(authenticationService.getScopes().contains(scopeB));
    assertTrue(authenticationService.getScopes().contains("ExampleAuthority"));
  }

  @Test
  public void wrongIssuerCheck() throws ServletException, IOException {
    String issuer = "not.example.com";
    String subject = UUID.randomUUID().toString();
    String scopeA = UUID.randomUUID().toString();
    String scopeB = UUID.randomUUID().toString();
    List<String> scopes = new ArrayList<>();
    scopes.add(scopeA);
    scopes.add(scopeB);
    Integer durationSeconds = 86400;
    String token = makeRSA256FilterToken(subject, scopes, issuer, durationSeconds);
    HttpServletRequest mockRequest = mock(HttpServletRequest.class);
    HttpServletResponse mockResponse = mock(HttpServletResponse.class);
    FilterChain mockChain = mock(FilterChain.class);
    when(mockRequest.getHeader(Mockito.eq(AuthenticationHeader))).thenReturn(token);
    when(mockRequest.getDispatcherType()).thenReturn(DispatcherType.REQUEST);
    service84JWTAuthenticationFilter.doFilter(mockRequest, mockResponse, mockChain);
    Assertions.assertNull(authenticationService.getSubject());
    assertTrue(authenticationService.getScopes().isEmpty());
  }

  @Test
  public void wrongKeyCheck() throws ServletException, IOException {
    String issuer = "example.com";
    String subject = UUID.randomUUID().toString();
    String scopeA = UUID.randomUUID().toString();
    String scopeB = UUID.randomUUID().toString();
    List<String> scopes = new ArrayList<>();
    scopes.add(scopeA);
    scopes.add(scopeB);
    Integer durationSeconds = 86400;
    String token = makeNotFilterToken(subject, scopes, issuer, durationSeconds);
    HttpServletRequest mockRequest = mock(HttpServletRequest.class);
    HttpServletResponse mockResponse = mock(HttpServletResponse.class);
    FilterChain mockChain = mock(FilterChain.class);
    when(mockRequest.getHeader(Mockito.eq(AuthenticationHeader))).thenReturn(token);
    when(mockRequest.getDispatcherType()).thenReturn(DispatcherType.REQUEST);
    service84JWTAuthenticationFilter.doFilter(mockRequest, mockResponse, mockChain);
    Assertions.assertNull(authenticationService.getSubject());
    assertTrue(authenticationService.getScopes().isEmpty());
  }
}
