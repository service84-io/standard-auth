package io.service84.library.standardauth.api.rest.authentication;

import java.io.IOException;
import java.net.MalformedURLException;
import java.net.URI;
import java.net.URISyntaxException;
import java.net.URL;
import java.security.interfaces.RSAPrivateKey;
import java.security.interfaces.RSAPublicKey;
import java.time.LocalDateTime;
import java.util.Arrays;
import java.util.List;
import java.util.stream.Collectors;

import javax.servlet.FilterChain;
import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import org.apache.commons.lang3.ObjectUtils;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.web.authentication.www.BasicAuthenticationFilter;

import com.auth0.jwk.JwkException;
import com.auth0.jwk.JwkProvider;
import com.auth0.jwk.UrlJwkProvider;
import com.auth0.jwt.JWT;
import com.auth0.jwt.JWTVerifier;
import com.auth0.jwt.algorithms.Algorithm;
import com.auth0.jwt.interfaces.DecodedJWT;
import com.auth0.jwt.interfaces.RSAKeyProvider;

import io.service84.library.authutils.services.AuthenticationService;

public class Service84JWTAuthenticationFilter extends BasicAuthenticationFilter {
  private static String AUTHENTICATION_HEADER = "Authentication";
  private static String BEARER_PREFIX = "Bearer ";
  private static Integer defaultPublicKeyTTLDefault = 86400;
  private static Integer minSecondsRemainingDefault = 6;

  @Autowired private AuthenticationService authenticationService;

  private URL providerUrl;
  private String providerIssuer;
  private String providerAuthority;
  private Integer defaultPublicKeyTTL;
  private Integer minSecondsRemaining;

  private volatile RSAKeyProvider rsaKeyProvider = null;
  private volatile LocalDateTime rsaKeyProviderExpire = LocalDateTime.MIN;

  public Service84JWTAuthenticationFilter(
      String providerUrl,
      String providerAuthority,
      Integer defaultPublicKeyTTL,
      Integer minSecondsRemaining)
      throws URISyntaxException, MalformedURLException {
    super(
        new AuthenticationManager() {
          @Override
          public Authentication authenticate(Authentication authentication)
              throws AuthenticationException {
            return authentication;
          }
        });

    defaultPublicKeyTTL = ObjectUtils.firstNonNull(defaultPublicKeyTTL, defaultPublicKeyTTLDefault);
    minSecondsRemaining = ObjectUtils.firstNonNull(minSecondsRemaining, minSecondsRemainingDefault);

    if (!providerUrl.startsWith("http")) {
      providerUrl = "https://" + providerUrl + "/.well-known/jwks.json";
    }

    URI providerUri = new URI(providerUrl).normalize();
    this.providerUrl = providerUri.toURL();
    this.providerIssuer = this.providerUrl.getHost();
    this.providerAuthority = providerAuthority;
    this.defaultPublicKeyTTL = defaultPublicKeyTTL;
    this.minSecondsRemaining = minSecondsRemaining;
  }

  @Override
  protected void doFilterInternal(
      HttpServletRequest request, HttpServletResponse response, FilterChain chain)
      throws IOException, ServletException {
    String authorization = request.getHeader(AUTHENTICATION_HEADER);

    if ((authorization != null) && (authorization.startsWith(BEARER_PREFIX))) {
      String token = authorization.replaceFirst(BEARER_PREFIX, "");
      try {
        RSAKeyProvider keyProvider = getRSA256KeyProvider();
        Algorithm algorithm = Algorithm.RSA256(keyProvider);
        JWTVerifier verifier = JWT.require(algorithm).withIssuer(providerIssuer).build();
        DecodedJWT jwt = verifier.verify(token);
        String user = jwt.getSubject();
        List<String> scopeStrings =
            Arrays.asList(
                ObjectUtils.firstNonNull(jwt.getClaim("scope").asString(), "").split(" "));
        List<GrantedAuthority> authorities =
            scopeStrings
                .stream()
                .map(p -> p.trim())
                .filter(p -> !p.isEmpty())
                .map(p -> new SimpleGrantedAuthority(p))
                .collect(Collectors.toList());

        if (providerAuthority != null) {
          authorities.add(new SimpleGrantedAuthority(providerAuthority));
        }

        Authentication authentication =
            new UsernamePasswordAuthenticationToken(user, authorization, authorities);
        authenticationService.setAuthentication(authentication);
      } catch (Exception e) {
        // Continue
      }
    }

    chain.doFilter(request, response);
  }

  private RSAKeyProvider getRSA256KeyProvider() {
    if ((rsaKeyProvider == null)
        || rsaKeyProviderExpire.isBefore(LocalDateTime.now().minusSeconds(minSecondsRemaining))) {
      syncFetchRSA256KeyProvider();
    }

    return rsaKeyProvider;
  }

  private synchronized void syncFetchRSA256KeyProvider() {
    if ((rsaKeyProvider == null)
        || rsaKeyProviderExpire.isBefore(LocalDateTime.now().minusSeconds(minSecondsRemaining))) {
      rsaKeyProvider = wrapKeyProvider(new UrlJwkProvider(providerUrl));
      rsaKeyProviderExpire = LocalDateTime.now().plusSeconds(defaultPublicKeyTTL);
    }
  }

  private RSAKeyProvider wrapKeyProvider(JwkProvider jwkProvider) {
    return new RSAKeyProvider() {
      @Override
      public RSAPrivateKey getPrivateKey() {
        return null;
      }

      @Override
      public String getPrivateKeyId() {
        return null;
      }

      @Override
      public RSAPublicKey getPublicKeyById(String keyId) {
        try {
          return (RSAPublicKey) jwkProvider.get(keyId).getPublicKey();
        } catch (JwkException e) {
          return null;
        }
      }
    };
  }
}
