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

import java.net.URL;
import java.security.interfaces.RSAPrivateKey;
import java.security.interfaces.RSAPublicKey;
import java.util.UUID;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.stereotype.Service;

import com.auth0.jwk.JwkException;
import com.auth0.jwk.JwkProvider;
import com.auth0.jwk.UrlJwkProvider;
import com.auth0.jwt.interfaces.RSAKeyProvider;

@Service("551A55CF-2E58-4EE8-9637-31F3E2EC35C8")
class KeyProviderService {
  private static final Logger logger = LoggerFactory.getLogger(KeyProviderService.class);

  public RSAKeyProvider wrapJWKProvider(URL providerURL) {
    logger.debug("wrapJWKProvider");
    JwkProvider jwkProvider = new UrlJwkProvider(providerURL);

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

  public RSAKeyProvider wrapKeys(RSAPrivateKey privateKey, RSAPublicKey publicKey) {
    logger.debug("wrapKeys");
    return new RSAKeyProvider() {
      private String keyId = UUID.randomUUID().toString();

      @Override
      public RSAPrivateKey getPrivateKey() {
        return privateKey;
      }

      @Override
      public String getPrivateKeyId() {
        if (privateKey == null) {
          return null;
        }

        return keyId;
      }

      @Override
      public RSAPublicKey getPublicKeyById(String keyId) {
        if (this.keyId.equals(keyId)) {
          return publicKey;
        }

        return null;
      }
    };
  }
}
