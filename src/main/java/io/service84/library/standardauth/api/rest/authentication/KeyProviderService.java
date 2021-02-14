package io.service84.library.standardauth.api.rest.authentication;

import java.net.URL;
import java.security.interfaces.RSAPrivateKey;
import java.security.interfaces.RSAPublicKey;
import java.util.UUID;

import org.springframework.stereotype.Service;

import com.auth0.jwk.JwkException;
import com.auth0.jwk.JwkProvider;
import com.auth0.jwk.UrlJwkProvider;
import com.auth0.jwt.interfaces.RSAKeyProvider;

@Service("551A55CF-2E58-4EE8-9637-31F3E2EC35C8")
class KeyProviderService {
  public RSAKeyProvider wrapJWKProvider(URL providerURL) {
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
