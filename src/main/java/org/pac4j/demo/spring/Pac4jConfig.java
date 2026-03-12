package org.pac4j.demo.spring;

import com.nimbusds.jose.JWSAlgorithm;
import com.nimbusds.jose.jwk.RSAKey;
import com.nimbusds.oauth2.sdk.auth.ClientAuthenticationMethod;
import lombok.val;
import org.pac4j.cas.client.CasClient;
import org.pac4j.cas.config.CasConfiguration;
import org.pac4j.core.client.Clients;
import org.pac4j.core.client.direct.AnonymousClient;
import org.pac4j.core.config.Config;
import org.pac4j.core.config.properties.JwksProperties;
import org.pac4j.core.util.JwkHelper;
import org.pac4j.http.client.direct.DirectBasicAuthClient;
import org.pac4j.http.client.direct.ParameterClient;
import org.pac4j.http.client.indirect.FormClient;
import org.pac4j.http.client.indirect.IndirectBasicAuthClient;
import org.pac4j.http.credentials.authenticator.test.SimpleTestUsernamePasswordAuthenticator;
import org.pac4j.jwt.config.encryption.SecretEncryptionConfiguration;
import org.pac4j.jwt.config.signature.SecretSignatureConfiguration;
import org.pac4j.jwt.credentials.authenticator.JwtAuthenticator;
import org.pac4j.oauth.client.FacebookClient;
import org.pac4j.oauth.client.TwitterClient;
import org.pac4j.oidc.client.GoogleOidcClient;
import org.pac4j.oidc.client.OidcClient;
import org.pac4j.oidc.config.OidcConfiguration;
import org.pac4j.oidc.config.PrivateKeyJWTClientAuthnMethodConfig;
import org.pac4j.oidc.config.method.PrivateKeyJwtClientAuthnMethodConfig;
import org.pac4j.oidc.federation.config.OidcTrustAnchorProperties;
import org.pac4j.saml.client.SAML2Client;
import org.pac4j.saml.config.SAML2Configuration;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.core.io.ClassPathResource;
import org.springframework.core.io.FileSystemResource;

import java.io.File;
import java.util.List;
import java.util.Optional;

import static org.pac4j.demo.spring.DemoOidcOpType.*;

@Configuration
public class Pac4jConfig {

    @Value("${server.port:8080}")
    private String serverPort;

    @Value("${salt}")
    private String salt;

    private static final DemoOidcOpType type = CAS_HEROKU; //OIDCPLANTEST_BASIC;

    public static final String OIDC_ENV = "staging";
    //public static final String OIDC_ENV = "www";

    private OidcConfiguration buildOidcConfiguration(final OidcConfiguration config) throws Exception {
        if (type == OIDCPLANTEST_BASIC) {

            config.setDiscoveryURI("https://" + OIDC_ENV + ".certification.openid.net/test/a/rppac4jbas/.well-known/openid-configuration");
            config.setClientId("myclient");
            config.setSecret("mysecret");
            config.setUseNonce(true);
            config.setAllowUnsignedIdTokens(true);
            // for request_object:
            /*config.setRequestObjectSigningAlgorithm(JWSAlgorithm.RS256);
            val rpJwks = config.getRpJwks();
            rpJwks.setJwksPath("file:./metadata/rpjwks.jwks");
            rpJwks.setKid("defaultjwks0326");*/

        } else if (type == OIDCPLANTEST_FEDE) {

            val rpJwks = config.getRpJwks();
            rpJwks.setJwksPath("file:./metadata/rpjwks.jwks");
            rpJwks.setKid("defaultjwks0326");
            config.setClientAuthenticationMethod(ClientAuthenticationMethod.PRIVATE_KEY_JWT);
            val privateKeyJwtConfig = new PrivateKeyJwtClientAuthnMethodConfig(rpJwks);
            config.setPrivateKeyJWTClientAuthnMethodConfig(privateKeyJwtConfig);

            val federation = config.getFederation();

            federation.setTargetIssuer("https://" + OIDC_ENV + ".certification.openid.net/test/a/rppac4jfede");
            val trust = new OidcTrustAnchorProperties();
            trust.setTaIssuer("https://" + OIDC_ENV + ".certification.openid.net/test/a/rppac4jfede/trust-anchor");
            trust.setTaJwksUrl("http://localhost:" + serverPort + "/rppac4jfede/jwks.json");
            federation.getTrustAnchors().add(trust);

            config.setAllowUnsignedIdTokens(true);

            federation.getJwks().setJwksPath("file:./metadata/oidcfede.jwks");
            federation.getJwks().setKid("mykeyoidcfede26");
            federation.setClientName("Federated Test RP (Localhost)");
            federation.setContacts(List.of("jerome@casinthecloud.com"));

            federation.setEntityId("https://client.ngrok-free.dev");

        } else if (type == CAS_HEROKU) {

            config.setDiscoveryURI("https://casserverpac4j.herokuapp.com/oidc/.well-known/openid-configuration");
            config.setClientId("myclient");
            config.setSecret("mysecret");
            config.setAllowUnsignedIdTokens(true);

        } else if (type == DemoOidcOpType.FAKE_FEDERATED_LOCAL) {

            val federation = config.getFederation();

            federation.setTargetIssuer("http://localhost:" + serverPort + "/op");
            val trust = new OidcTrustAnchorProperties();
            trust.setTaIssuer("http://localhost:" + serverPort + "/ta");
            trust.setTaJwksUrl("http://localhost:" + serverPort + "/ta/jwks.json");
            federation.getTrustAnchors().add(trust);

            config.setClientAuthenticationMethod(ClientAuthenticationMethod.PRIVATE_KEY_JWT);
            val jwksProperties = new JwksProperties();
            jwksProperties.setJwksPath("classpath:/static/op/keystore.jwks");
            jwksProperties.setKid("cas-qGcosGMN");
            val signingKey = JwkHelper.loadJwkFromOrCreateJwks(jwksProperties);
            val privateKeyJwtConfig = new PrivateKeyJWTClientAuthnMethodConfig(JWSAlgorithm.RS256, ((RSAKey) signingKey).toKeyPair().getPrivate(), "12345");
            config.setPrivateKeyJWTClientAuthnMethodConfig(privateKeyJwtConfig);

            config.setAllowUnsignedIdTokens(true);

            federation.getJwks().setJwksPath("file:./metadata/oidcfede.jwks");
            federation.getJwks().setKid("mykeyoidcfede26");
            federation.setClientName("Federated Test RP (Localhost)");
            federation.setContacts(List.of("jerome@casinthecloud.com"));

            //federation.getJwks().setJwksPath("file:/etc/cas/config/keystore.jwks");
            //federation.getJwks().setKid("cas-JdlXLICH");

            /*federation.getKeystore().setKeystorePath("file:./metadata/oidcfede.keystore");
            federation.getKeystore().setKeystorePassword("changeit");
            federation.getKeystore().setPrivateKeyPassword("changeit");*/

            federation.setEntityId("http://localhost:" + serverPort);
        }
        return config;
    }

    @Bean
    public Config config() throws Exception {
        val oidcConfig = buildOidcConfiguration(new OidcConfiguration());
        val oidcClient = new OidcClient(oidcConfig);

        val googleOidcConfiguration = new OidcConfiguration();
        googleOidcConfiguration.setClientId("167480702619-8e1lo80dnu8bpk3k0lvvj27noin97vu9.apps.googleusercontent.com");
        googleOidcConfiguration.setSecret("MhMme_Ik6IH2JMnAT6MFIfee");
        googleOidcConfiguration.setPreferredJwsAlgorithm(JWSAlgorithm.PS384);
        googleOidcConfiguration.addCustomParam("prompt", "consent");
        val googleOidcClient = new GoogleOidcClient(googleOidcConfiguration);
        googleOidcClient.setAuthorizationGenerator((ctx, profile) -> {
            profile.addRole("ROLE_ADMIN");
            return Optional.of(profile);
        });

        final SAML2Configuration cfg = new SAML2Configuration(new ClassPathResource("samlKeystore.jks"),
            "pac4j-demo-passwd",
            "pac4j-demo-passwd",
            new ClassPathResource("metadata-okta.xml"));
        cfg.setMaximumAuthenticationLifetime(3600);
        cfg.setServiceProviderEntityId("http://localhost:" + serverPort + "/callback?client_name=SAML2Client");
        cfg.setServiceProviderMetadataResource(new FileSystemResource(new File("./metadata/sp-metadata-" + serverPort + ".xml").getAbsoluteFile()));
        final SAML2Client saml2Client = new SAML2Client(cfg);

        final FacebookClient facebookClient = new FacebookClient("145278422258960", "be21409ba8f39b5dae2a7de525484da8");
        facebookClient.setMultiProfile(true);
        final TwitterClient twitterClient = new TwitterClient("CoxUiYwQOSFDReZYdjigBA",
            "2kAzunH5Btc4gRSaMr7D7MkyoJ5u1VzbOOzE8rBofs");
        // HTTP
        final FormClient formClient = new FormClient("http://localhost:" + serverPort + "/loginForm", new SimpleTestUsernamePasswordAuthenticator());
        final IndirectBasicAuthClient indirectBasicAuthClient = new IndirectBasicAuthClient(new SimpleTestUsernamePasswordAuthenticator());

        // CAS
        final CasConfiguration configuration = new CasConfiguration("https://casserverpac4j.herokuapp.com/login");
        final CasClient casClient = new CasClient(configuration);
        // casClient.setGateway(true);

        // REST authent with JWT for a token passed in the url as the token parameter
        final SecretSignatureConfiguration secretSignatureConfiguration = new SecretSignatureConfiguration(salt);
        final SecretEncryptionConfiguration secretEncryptionConfiguration = new SecretEncryptionConfiguration(salt);
        final JwtAuthenticator authenticator = new JwtAuthenticator();
        authenticator.setSignatureConfiguration(secretSignatureConfiguration);
        authenticator.setEncryptionConfiguration(secretEncryptionConfiguration);
        final ParameterClient parameterClient = new ParameterClient("token", authenticator);
        parameterClient.setSupportGetRequest(true);
        parameterClient.setSupportPostRequest(false);

        // basic auth
        final DirectBasicAuthClient directBasicAuthClient = new DirectBasicAuthClient(new SimpleTestUsernamePasswordAuthenticator());

        var callbackUrl = "http://localhost:" + serverPort + "/callback";
        if (type == OIDCPLANTEST_FEDE || type == OIDCPLANTEST_BASIC) {
            callbackUrl = "https://client.ngrok-free.dev/callback?client_name=OidcClient";
        }
        final Clients clients = new Clients(callbackUrl, googleOidcClient,
                oidcClient,
                saml2Client,
                facebookClient, twitterClient, formClient, indirectBasicAuthClient, casClient, parameterClient, directBasicAuthClient, new AnonymousClient());

        return new Config(clients);
    }
}
