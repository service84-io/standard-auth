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

/*
 * @deprecated Use Service84JWTAuthenticationFilter in the services package
 */
@Deprecated(since = "1.3.0")
public class Service84JWTAuthenticationFilter
    extends io.service84.library.standardauth.services.Service84JWTAuthenticationFilter {

  public Service84JWTAuthenticationFilter(
      String providerUrl,
      String providerAuthority,
      Integer defaultPublicKeyTTL,
      Integer minSecondsRemaining)
      throws URISyntaxException, MalformedURLException {
    super(providerUrl, providerAuthority, defaultPublicKeyTTL, minSecondsRemaining);
  }
}
