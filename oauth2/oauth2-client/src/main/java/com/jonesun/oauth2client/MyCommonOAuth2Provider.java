package com.jonesun.oauth2client;

import org.springframework.security.oauth2.client.registration.ClientRegistration;
import org.springframework.security.oauth2.core.AuthorizationGrantType;
import org.springframework.security.oauth2.core.ClientAuthenticationMethod;

/**
 * @author jone.sun
 * @date 2020-12-30 09:45
 */
public enum MyCommonOAuth2Provider {


    GITEE {
        @Override
        public ClientRegistration.Builder getBuilder(String registrationId) {
            ClientRegistration.Builder builder = getBuilder(registrationId, ClientAuthenticationMethod.BASIC,
                    DEFAULT_REDIRECT_URL);
            builder.scope("user_info");
            builder.authorizationUri("https://gitee.com/oauth/authorize");
            builder.tokenUri("https://gitee.com/oauth/token");
            builder.userInfoUri("https://gitee.com/api/v5/user");
            builder.userNameAttributeName("name");
            builder.clientName("Gitee");
            return builder;
        }

    };

    private static final String DEFAULT_REDIRECT_URL = "{baseUrl}/{action}/oauth2/code/{registrationId}";

    protected final ClientRegistration.Builder getBuilder(String registrationId, ClientAuthenticationMethod method,
                                                          String redirectUri) {
        ClientRegistration.Builder builder = ClientRegistration.withRegistrationId(registrationId);
        builder.clientAuthenticationMethod(method);
        builder.authorizationGrantType(AuthorizationGrantType.AUTHORIZATION_CODE);
        builder.redirectUri(redirectUri);
        return builder;
    }

    /**
     * Create a new
     * {@link org.springframework.security.oauth2.client.registration.ClientRegistration.Builder
     * ClientRegistration.Builder} pre-configured with provider defaults.
     *
     * @param registrationId the registration-id used with the new builder
     * @return a builder instance
     */
    public abstract ClientRegistration.Builder getBuilder(String registrationId);

}
