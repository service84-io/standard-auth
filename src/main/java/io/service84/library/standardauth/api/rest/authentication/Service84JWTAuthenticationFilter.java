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

import java.io.IOException;
import java.net.MalformedURLException;
import java.net.URI;
import java.net.URISyntaxException;
import java.net.URL;
import java.time.LocalDateTime;
import java.util.Arrays;
import java.util.List;
import java.util.stream.Collectors;

import javax.servlet.FilterChain;
import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import org.apache.commons.lang3.ObjectUtils;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.web.authentication.www.BasicAuthenticationFilter;

import com.auth0.jwt.JWT;
import com.auth0.jwt.JWTVerifier;
import com.auth0.jwt.algorithms.Algorithm;
import com.auth0.jwt.interfaces.DecodedJWT;
import com.auth0.jwt.interfaces.RSAKeyProvider;

import io.service84.library.authutils.services.AuthenticationService;

public class Service84JWTAuthenticationFilter extends BasicAuthenticationFilter {
  private static final Logger logger =
      LoggerFactory.getLogger(Service84JWTAuthenticationFilter.class);

  private static String AuthenticationHeader = "Authentication";
  private static String BearerPrefix = "Bearer ";
  private static Integer DefaultPublicKeyTTLDefault = 86400;
  private static Integer MinSecondsRemainingDefault = 6;
  private static List<String> PermittedAlgorithms = Arrays.asList("RS256", "RS384", "RS512");

  @Autowired private AuthenticationService authenticationService;
  @Autowired private KeyProviderService keyProviderService;

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

    defaultPublicKeyTTL = ObjectUtils.firstNonNull(defaultPublicKeyTTL, DefaultPublicKeyTTLDefault);
    minSecondsRemaining = ObjectUtils.firstNonNull(minSecondsRemaining, MinSecondsRemainingDefault);

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
    logger.debug("doFilterInternal");
    String authorization = request.getHeader(AuthenticationHeader);

    if ((authorization != null) && (authorization.startsWith(BearerPrefix))) {
      String token = authorization.replaceFirst(BearerPrefix, "");
      try {
        DecodedJWT unverifiedJWT = JWT.decode(token);
        Algorithm algorithm = getAlgorithm(unverifiedJWT);

        if (isPermittedAlgorithm(algorithm)) {
          JWTVerifier verifier = JWT.require(algorithm).withIssuer(providerIssuer).build();
          DecodedJWT verifiedJWT = verifier.verify(unverifiedJWT);
          String user = verifiedJWT.getSubject();
          List<String> scopeStrings =
              Arrays.asList(
                  ObjectUtils.firstNonNull(verifiedJWT.getClaim("scope").asString(), "")
                      .split(" "));
          List<GrantedAuthority> authorities =
              scopeStrings.stream()
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
        }
      } catch (Exception e) {
        // Continue
      }
    }

    chain.doFilter(request, response);
  }

  private Algorithm getAlgorithm(DecodedJWT jwt) {
    if (jwt.getAlgorithm().equals("RS256")) {
      RSAKeyProvider keyProvider = getRSAKeyProvider();
      return Algorithm.RSA256(keyProvider);
    }

    if (jwt.getAlgorithm().equals("RS384")) {
      RSAKeyProvider keyProvider = getRSAKeyProvider();
      return Algorithm.RSA384(keyProvider);
    }

    if (jwt.getAlgorithm().equals("RS512")) {
      RSAKeyProvider keyProvider = getRSAKeyProvider();
      return Algorithm.RSA512(keyProvider);
    }

    if (jwt.getAlgorithm().equals("HS256")) {
      return Algorithm.HMAC256("");
    }

    if (jwt.getAlgorithm().equals("HS384")) {
      return Algorithm.HMAC384("");
    }

    if (jwt.getAlgorithm().equals("HS512")) {
      return Algorithm.HMAC512("");
    }

    if (jwt.getAlgorithm().equals("ES256")) {
      return Algorithm.ECDSA256(null, null);
    }

    if (jwt.getAlgorithm().equals("ES384")) {
      return Algorithm.ECDSA384(null, null);
    }

    if (jwt.getAlgorithm().equals("ES512")) {
      return Algorithm.ECDSA512(null, null);
    }

    return Algorithm.none();
  }

  private RSAKeyProvider getRSAKeyProvider() {
    if ((rsaKeyProvider == null)
        || rsaKeyProviderExpire.isBefore(LocalDateTime.now().minusSeconds(minSecondsRemaining))) {
      syncFetchRSAKeyProvider();
    }

    return rsaKeyProvider;
  }

  private Boolean isPermittedAlgorithm(Algorithm algorithm) {
    return PermittedAlgorithms.contains(algorithm.getName());
  }

  private synchronized void syncFetchRSAKeyProvider() {
    if ((rsaKeyProvider == null)
        || rsaKeyProviderExpire.isBefore(LocalDateTime.now().minusSeconds(minSecondsRemaining))) {
      rsaKeyProvider = keyProviderService.wrapJWKProvider(providerUrl);
      rsaKeyProviderExpire = LocalDateTime.now().plusSeconds(defaultPublicKeyTTL);
    }
  }
}
