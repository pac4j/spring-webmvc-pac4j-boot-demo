package org.pac4j.demo.spring;

import com.nimbusds.jose.JWSAlgorithm;
import org.pac4j.cas.client.CasClient;
import org.pac4j.core.authorization.authorizer.RequireAnyRoleAuthorizer;
import org.pac4j.core.client.Clients;
import org.pac4j.core.config.Config;
import org.pac4j.http.client.direct.DirectBasicAuthClient;
import org.pac4j.http.client.direct.ParameterClient;
import org.pac4j.http.client.indirect.FormClient;
import org.pac4j.http.client.indirect.IndirectBasicAuthClient;
import org.pac4j.http.credentials.authenticator.test.SimpleTestUsernamePasswordAuthenticator;
import org.pac4j.jwt.credentials.authenticator.JwtAuthenticator;
import org.pac4j.oauth.client.FacebookClient;
import org.pac4j.oauth.client.TwitterClient;
import org.pac4j.oidc.client.GoogleOidcClient;
import org.pac4j.oidc.config.OidcConfiguration;
import org.pac4j.saml.client.SAML2Client;
import org.pac4j.saml.client.SAML2ClientConfiguration;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;

@Configuration
public class Pac4jConfig {

    @Value("${salt}")
    private String salt;

    @Bean
    public Config config() {
        /*final OidcConfiguration oidcConfiguration = new OidcConfiguration();
        oidcConfiguration.setClientId("test");
        oidcConfiguration.setSecret("secret");
        oidcConfiguration.setUseNonce(true);
        oidcConfiguration.setDiscoveryURI("http://localhost:5000/.well-known/openid-configuration");
        oidcConfiguration.setScope("openid api1");
        oidcConfiguration.setClientAuthenticationMethod(ClientAuthenticationMethod.CLIENT_SECRET_BASIC);
        oidcConfiguration.addCustomParam("prompt", "consent");
        final OidcClient oidcClient = new OidcClient(oidcConfiguration);
        oidcClient.setName("test");
        oidcClient.setCallbackUrl("http://localhost:8080/callback");*/

        final OidcConfiguration oidcConfiguration = new OidcConfiguration();
        oidcConfiguration.setClientId("167480702619-8e1lo80dnu8bpk3k0lvvj27noin97vu9.apps.googleusercontent.com");
        oidcConfiguration.setSecret("MhMme_Ik6IH2JMnAT6MFIfee");
        oidcConfiguration.setPreferredJwsAlgorithm(JWSAlgorithm.PS384);
        oidcConfiguration.addCustomParam("prompt", "consent");
        final GoogleOidcClient oidcClient = new GoogleOidcClient(oidcConfiguration);
        oidcClient.setAuthorizationGenerator(profile -> profile.addRole("ROLE_ADMIN"));

        final SAML2ClientConfiguration cfg = new SAML2ClientConfiguration("resource:samlKeystore.jks",
                "pac4j-demo-passwd",
                "pac4j-demo-passwd",
                "resource:metadata-okta.xml");
        cfg.setMaximumAuthenticationLifetime(3600);
        cfg.setServiceProviderEntityId("http://localhost:8080/callback?client_name=SAML2Client");
        cfg.setServiceProviderMetadataPath("sp-metadata.xml");
        final SAML2Client saml2Client = new SAML2Client(cfg);

        final FacebookClient facebookClient = new FacebookClient("145278422258960", "be21409ba8f39b5dae2a7de525484da8");
        final TwitterClient twitterClient = new TwitterClient("CoxUiYwQOSFDReZYdjigBA",
                "2kAzunH5Btc4gRSaMr7D7MkyoJ5u1VzbOOzE8rBofs");
        // HTTP
        final FormClient formClient = new FormClient("http://localhost:8080/loginForm.jsp", new SimpleTestUsernamePasswordAuthenticator());
        final IndirectBasicAuthClient indirectBasicAuthClient = new IndirectBasicAuthClient(new SimpleTestUsernamePasswordAuthenticator());

        // CAS
        final CasClient casClient = new CasClient("https://casserverpac4j.herokuapp.com/login");
        // casClient.setGateway(true);

        // REST authent with JWT for a token passed in the url as the token parameter
        ParameterClient parameterClient = new ParameterClient("token", new JwtAuthenticator(salt));
        parameterClient.setSupportGetRequest(true);
        parameterClient.setSupportPostRequest(false);

        // basic auth
        final DirectBasicAuthClient directBasicAuthClient = new DirectBasicAuthClient(new SimpleTestUsernamePasswordAuthenticator());

        final Clients clients = new Clients("http://localhost:8080/callback", oidcClient, saml2Client, facebookClient,
                twitterClient, formClient, indirectBasicAuthClient, casClient, parameterClient, directBasicAuthClient);

        final Config config = new Config(clients);
        config.addAuthorizer("admin", new RequireAnyRoleAuthorizer("ROLE_ADMIN"));
        config.addAuthorizer("custom", new CustomAuthorizer());
        return config;
    }
}
