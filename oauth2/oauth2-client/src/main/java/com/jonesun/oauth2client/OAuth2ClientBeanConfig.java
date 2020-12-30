package com.jonesun.oauth2client;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.core.env.Environment;
import org.springframework.security.config.oauth2.client.CommonOAuth2Provider;
import org.springframework.security.oauth2.client.InMemoryOAuth2AuthorizedClientService;
import org.springframework.security.oauth2.client.OAuth2AuthorizedClientService;
import org.springframework.security.oauth2.client.registration.ClientRegistration;
import org.springframework.security.oauth2.client.registration.ClientRegistrationRepository;
import org.springframework.security.oauth2.client.registration.InMemoryClientRegistrationRepository;

import java.util.Arrays;
import java.util.List;
import java.util.Objects;
import java.util.stream.Collectors;

/**
 * @author jone.sun
 * @date 2020-12-30 10:38
 */
@Configuration
public class OAuth2ClientBeanConfig {

    private static final String CLIENT_PROPERTY_KEY = "spring.security.oauth2.client.registration.";

    private static final List<String> clients = Arrays.asList("github", "gitee");

    @Bean
    public ClientRegistrationRepository clientRegistrationRepository() {
        //todo 这里可以通过动态获取CLIENT_PROPERTY_KEY对应配置，更加灵活的设置ClientRegistrationRepository
        List<ClientRegistration> registrations = clients.stream()
                .map(this::getRegistration)
                .filter(Objects::nonNull)
                .collect(Collectors.toList());

        return new InMemoryClientRegistrationRepository(registrations);
    }

    @Autowired
    private Environment environment;

    private ClientRegistration getRegistration(String client) {
        String clientId = environment.getProperty(
                CLIENT_PROPERTY_KEY + client + ".client-id");

        if (clientId == null) {
            return null;
        }

        String clientSecret = environment.getProperty(
                CLIENT_PROPERTY_KEY + client + ".client-secret");

        if (client.equals("github")) {
            return CommonOAuth2Provider.GITHUB.getBuilder(client)
                    .clientId(clientId).clientSecret(clientSecret).build();
        }
        if (client.equals("gitee")) {
            return MyCommonOAuth2Provider.GITEE.getBuilder(client)
                    .clientId(clientId).clientSecret(clientSecret).build();
        }
        return null;
    }

    @Bean
    public OAuth2AuthorizedClientService authorizedClientService() {
        return new InMemoryOAuth2AuthorizedClientService(clientRegistrationRepository());
    }

}
