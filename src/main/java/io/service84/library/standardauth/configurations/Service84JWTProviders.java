package io.service84.library.standardauth.configurations;

import java.util.Map;

import org.springframework.boot.context.properties.ConfigurationProperties;

@ConfigurationProperties(prefix = "io.service84.library.standardauth.jwt")
public class Service84JWTProviders {
  public static class Service84JWTProvider {
    private String url;
    private String authority;
    private Integer defaultPublicKeyTTL;
    private Integer minSecondsRemaining;

    public String getAuthority() {
      return authority;
    }

    public Integer getDefaultPublicKeyTTL() {
      return defaultPublicKeyTTL;
    }

    public Integer getMinSecondsRemaining() {
      return minSecondsRemaining;
    }

    public String getUrl() {
      return url;
    }

    public void setAuthority(String authority) {
      this.authority = authority;
    }

    public void setDefaultPublicKeyTTL(Integer defaultPublicKeyTTL) {
      this.defaultPublicKeyTTL = defaultPublicKeyTTL;
    }

    public void setMinSecondsRemaining(Integer minSecondsRemaining) {
      this.minSecondsRemaining = minSecondsRemaining;
    }

    public void setUrl(String url) {
      this.url = url;
    }
  }

  private Map<String, Service84JWTProvider> providers;

  public Map<String, Service84JWTProvider> getProviders() {
    return providers;
  }

  public void setProviders(Map<String, Service84JWTProvider> providers) {
    this.providers = providers;
  }
}
