package io.service84.library.standardauth.api.rest.authentication;

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

import javax.servlet.FilterChain;
import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.Mockito;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.TestConfiguration;
import org.springframework.context.annotation.Bean;
import org.springframework.test.context.junit.jupiter.SpringExtension;

import com.auth0.jwt.JWT;
import com.auth0.jwt.algorithms.Algorithm;
import com.auth0.jwt.interfaces.RSAKeyProvider;

import io.service84.library.authutils.services.AuthenticationService;

@ExtendWith(SpringExtension.class)
public class Service84JWTAuthenticationFilterNoAuthorityTests {
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

    @Bean
    public RSAKeyProvider getRSAKeyProvider() throws NoSuchAlgorithmException {
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
      return new Service84JWTAuthenticationFilter("https://example.com", null, null, null);
    }
  }

  private static String AuthenticationHeader = "Authentication";
  private static String BearerPrefix = "Bearer ";

  // Test Subject
  @Autowired private Service84JWTAuthenticationFilter service84JWTAuthenticationFilter;

  @Autowired private AuthenticationService authenticationService;
  @Autowired private KeyProviderService mockKeyProviderService;

  @Autowired private RSAKeyProvider rsaKeyProvider;

  @Test
  public void existenceTest() {
    assertNotNull(service84JWTAuthenticationFilter);
    assertNotNull(authenticationService);
    assertNotNull(mockKeyProviderService);
    assertNotNull(rsaKeyProvider);
  }

  private String makeToken(
      String subject, List<String> scopes, String issuer, Integer durationSeconds) {
    Date expiration = Date.from(ZonedDateTime.now().plusSeconds(durationSeconds).toInstant());
    Algorithm algorithm = Algorithm.RSA256(rsaKeyProvider);
    return BearerPrefix
        + JWT.create()
            .withIssuer(issuer)
            .withExpiresAt(expiration)
            .withSubject(subject.toString())
            .withClaim("scope", String.join(" ", scopes))
            .sign(algorithm);
  }

  @BeforeEach
  public void setup() {
    reset(mockKeyProviderService);
    when(mockKeyProviderService.wrapJWKProvider(any())).thenReturn(rsaKeyProvider);
    authenticationService.setAuthentication(null);
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
    String token = makeToken(subject, scopes, issuer, durationSeconds);
    HttpServletRequest mockRequest = mock(HttpServletRequest.class);
    HttpServletResponse mockResponse = mock(HttpServletResponse.class);
    FilterChain mockChain = mock(FilterChain.class);
    when(mockRequest.getHeader(Mockito.eq(AuthenticationHeader))).thenReturn(token);
    service84JWTAuthenticationFilter.doFilter(mockRequest, mockResponse, mockChain);
    assertEquals(subject, authenticationService.getSubject());
    assertEquals(2, authenticationService.getScopes().size());
    assertTrue(authenticationService.getScopes().contains(scopeA));
    assertTrue(authenticationService.getScopes().contains(scopeB));
  }
}
