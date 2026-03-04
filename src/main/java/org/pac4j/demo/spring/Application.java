package org.pac4j.demo.spring;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.nimbusds.jose.jwk.JWK;
import com.nimbusds.jose.jwk.JWKSet;
import com.nimbusds.jwt.JWTClaimsSet;
import lombok.val;
import org.pac4j.core.client.Client;
import org.pac4j.core.config.Config;
import org.pac4j.core.config.properties.JwksProperties;
import org.pac4j.core.context.CallContext;
import org.pac4j.core.exception.http.HttpAction;
import org.pac4j.core.profile.ProfileManager;
import org.pac4j.core.profile.UserProfile;
import org.pac4j.core.util.Pac4jConstants;
import org.pac4j.http.client.indirect.FormClient;
import org.pac4j.jee.context.JEEContext;
import org.pac4j.jee.context.session.JEESessionStore;
import org.pac4j.jee.http.adapter.JEEHttpActionAdapter;
import org.pac4j.jwt.config.encryption.SecretEncryptionConfiguration;
import org.pac4j.jwt.config.signature.SecretSignatureConfiguration;
import org.pac4j.jwt.profile.JwtGenerator;
import org.pac4j.oidc.client.OidcClient;
import org.pac4j.oidc.federation.entity.DefaultEntityConfigurationGenerator;
import org.pac4j.oidc.util.JwkHelper;
import org.pac4j.springframework.annotation.RequireAnyRole;
import org.pac4j.springframework.web.LogoutController;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.core.io.ClassPathResource;
import org.springframework.stereotype.Controller;
import org.springframework.web.bind.annotation.ExceptionHandler;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.ResponseBody;

import javax.annotation.PostConstruct;
import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.text.ParseException;
import java.util.*;

@Controller
public class Application {

    private static final String TYPE = DefaultEntityConfigurationGenerator.CONTENT_TYPE;
    //private static final String TYPE = MediaType.APPLICATION_JSON_VALUE;

    @Value("${salt}")
    private String salt;

    @Value("${pac4j.centralLogout.defaultUrl:#{null}}")
    private String defaultUrl;

    @Value("${pac4j.centralLogout.logoutUrlPattern:#{null}}")
    private String logoutUrlPattern;

    @Autowired
    private Config config;

    @Autowired
    private JEEContext webContext;

    @Autowired
    private ProfileManager profileManager;

    @Value("${server.port:8080}")
    private String serverPort;

    private LogoutController logoutController;

    @PostConstruct
    protected void afterPropertiesSet() {
        logoutController = new LogoutController();
        logoutController.setDefaultUrl(defaultUrl);
        logoutController.setLogoutUrlPattern(logoutUrlPattern);
        logoutController.setLocalLogout(false);
        logoutController.setCentralLogout(true);
        logoutController.setConfig(config);
        logoutController.setDestroySession(false);
    }

    @RequestMapping(value = {"/op/op-from-ta.jwt", "/ta/fetch"}, produces = TYPE)
    @ResponseBody
    public String opFromTa() throws IOException {
        val opConfig = getStaticFile("op/heroku_configuration.json");
        val jsonConfig = new ObjectMapper().readValue(opConfig, Map.class);

        val opKey = loadKey("op/keystore.jwks", "cas-qGcosGMN");
        val taKey = loadKey("ta/jwks.json", "ta-key-1");

        val now = new Date();
        long validityMs = 365 * 24 * 60 * 60 * 1000L;
        val exp = new Date(now.getTime() + validityMs);
        val claimsBuilder = new JWTClaimsSet.Builder()
                .issuer("http://localhost:" + serverPort + "/ta")
                .subject("http://localhost:" + serverPort + "/op")
                .issueTime(now)
                .expirationTime(exp);
        claimsBuilder.claim("metadata", jsonConfig);

        val publicTa = taKey.toPublicJWK();
        val publicOp = opKey.toPublicJWK();
        val jwkSet = new JWKSet(List.of(publicTa, publicOp));
        claimsBuilder.claim("jwks", jwkSet.toJSONObject());
        val claims = claimsBuilder.build();

        return JwkHelper.buildSignedJwt(claims, taKey, DefaultEntityConfigurationGenerator.ENTITY_STATEMENT_TYPE);
    }

    @RequestMapping(value = "/op/.well-known/openid-federation", produces = TYPE)
    @ResponseBody
    public String opFedeConfig() throws IOException, ParseException {
        val herokuConfig = getStaticFile("op/heroku_configuration.json");
        val jsonConfig = new ObjectMapper().readValue(herokuConfig, Map.class);

        val opKey = loadKey("op/keystore.jwks", "cas-qGcosGMN");

        val now = new Date();
        long validityMs = 365 * 24 * 60 * 60 * 1000L;
        val exp = new Date(now.getTime() + validityMs);
        val iss = "http://localhost:" + serverPort + "/op";
        val claimsBuilder = new JWTClaimsSet.Builder()
                .issuer(iss)
                .subject(iss)
                .issueTime(now)
                .expirationTime(exp);
        val openidProvider = new LinkedHashMap<String, Object>();
        openidProvider.put("openid_provider", jsonConfig);
        claimsBuilder.claim("metadata", openidProvider);

        val publicOp = opKey.toPublicJWK();
        val jwkSet = new JWKSet(publicOp);
        claimsBuilder.claim("jwks", jwkSet.toJSONObject());

        val federation = new LinkedHashMap<String, Object>();
        federation.put("trust_anchors", List.of("http://localhost:" + serverPort + "/ta"));
        claimsBuilder.claim("federation", federation);

        claimsBuilder.claim("statements", List.of("http://localhost:" + serverPort + "/op-from-ta.jwt"));

        claimsBuilder.claim("authority_hints", List.of("http://localhost:" + serverPort + "/ta"));

        val claims = claimsBuilder.build();
        return JwkHelper.buildSignedJwt(claims, opKey, DefaultEntityConfigurationGenerator.ENTITY_STATEMENT_TYPE);
    }

    @RequestMapping(value = "/.well-known/openid-federation/ta", produces = TYPE)
    @ResponseBody
    public String taFedeConfig() throws IOException, ParseException {
        val taKey = loadKey("ta/jwks.json", "ta-key-1");

        val now = new Date();
        long validityMs = 365 * 24 * 60 * 60 * 1000L;
        val exp = new Date(now.getTime() + validityMs);
        val iss = "http://localhost:" + serverPort + "/ta";
        val claimsBuilder = new JWTClaimsSet.Builder()
                .issuer(iss)
                .subject(iss)
                .issueTime(now)
                .expirationTime(exp);

        val federationEntity = new LinkedHashMap<String, Object>();
        federationEntity.put("federation_fetch_endpoint", iss + "/fetch");
        federationEntity.put("federation_list_endpoint", iss + "/list");

        val openidProvider = new LinkedHashMap<String, Object>();
        openidProvider.put("federation_entity", federationEntity);

        claimsBuilder.claim("metadata", openidProvider);

        val publicTa = taKey.toPublicJWK();
        val jwkSet = new JWKSet(publicTa);
        claimsBuilder.claim("jwks", jwkSet.toJSONObject());

        val claims = claimsBuilder.build();

        return JwkHelper.buildSignedJwt(claims, taKey, DefaultEntityConfigurationGenerator.ENTITY_STATEMENT_TYPE);
    }

    private JWK loadKey(final String jwks, final String kid) {
        val jwksProperties = new JwksProperties();
        jwksProperties.setJwksPath("classpath:static/" + jwks);
        jwksProperties.setKid(kid);
        return JwkHelper.loadCreateJwkFromJwks(jwksProperties);
    }

    private String getStaticFile(final String name) throws IOException {
        val rsc = new ClassPathResource("static/" + name);
        val inputStream = rsc.getInputStream();
        val originalBytes = inputStream.readAllBytes();
        inputStream.close();
        val json = new String(originalBytes, StandardCharsets.UTF_8);
        return json.replace("$PORT", serverPort);
    }

    @RequestMapping("/")
    public String root(final Map<String, Object> map) throws HttpAction {
        return index(map);
    }

    @RequestMapping(value = "/.well-known/openid-federation",  produces = TYPE)
    @ResponseBody
    public String oidcFederation() throws HttpAction {
        val oidcClient = (OidcClient) config.getClients().findClient("OidcClient").get();
        return oidcClient.getConfiguration().getFederation().getEntityConfigurationGenerator().generate();
    }

    @RequestMapping("/index.html")
    public String index(final Map<String, Object> map) throws HttpAction {
        map.put("profiles", profileManager.getProfiles());
        map.put("sessionId", new JEESessionStore().getSessionId(webContext, false).orElse("nosession"));
        return "index";
    }

    @RequestMapping("/facebook/index.html")
    public String facebook(final Map<String, Object> map) {
        return protectedIndex(map);
    }

    @RequestMapping("/facebook/notprotected.html")
    public String facebookNotProtected(final Map<String, Object> map) {
        map.put("profiles", profileManager.getProfiles());
        return "notProtected";
    }

    @RequestMapping("/facebookadmin/index.html")
    @RequireAnyRole("ROLE_ADMIN")
    public String facebookadmin(final Map<String, Object> map) {
        return protectedIndex(map);
    }

    @RequestMapping({"/facebookcustom/index.html", "/twitter/index.html", "/form/index.html", "/basicauth/index.html",
            "/saml/index.html", "/cas/index.html", "/oidc/index.html", "/googleoidc/index.html", "/protected/index.html"})
    public String protect(final Map<String, Object> map) {
        return protectedIndex(map);
    }

    @RequestMapping("/loginForm")
    public String loginForm(final Map<String, Object> map) {
        final FormClient formClient = (FormClient) config.getClients().findClient("FormClient").get();
        map.put("callbackUrl", formClient.getCallbackUrl());
        return "form";
    }

    @RequestMapping("/forceLogin")
    @ResponseBody
    public void forceLogin() {
        try {
            final String name = webContext.getRequestParameter(Pac4jConstants.DEFAULT_CLIENT_NAME_PARAMETER)
                .map(String::valueOf).orElse("");
            final Client client = config.getClients().findClient(name).get();
            JEEHttpActionAdapter.INSTANCE.adapt(client.getRedirectionAction(new CallContext(webContext, new JEESessionStore())).get(), webContext);
        } catch (final HttpAction e) {
        }
    }

    protected String protectedIndex(final Map<String, Object> map) {
        map.put("profiles", profileManager.getProfiles());
        return "protectedIndex";
    }

    @RequestMapping("/centralLogout")
    @ResponseBody
    public void centralLogout() {
        logoutController.logout(webContext.getNativeRequest(), webContext.getNativeResponse());
    }

    @RequestMapping("/dba/index.html")
    public String dba(final Map<String, Object> map) {
        return protectedIndex(map);
    }

    @RequestMapping("/rest-jwt/index.html")
    public String restJwt(final Map<String, Object> map) {
        return protectedIndex(map);
    }

    @RequestMapping("/casrest/index.html")
    public String casrest(final Map<String, Object> map) {
        return protectedIndex(map);
    }

    @RequestMapping("/jwt.html")
    public String jwt(final Map<String, Object> map) {
        final SecretSignatureConfiguration secretSignatureConfiguration = new SecretSignatureConfiguration(salt);
        final SecretEncryptionConfiguration secretEncryptionConfiguration = new SecretEncryptionConfiguration(salt);
        final JwtGenerator generator = new JwtGenerator();
        generator.setSignatureConfiguration(secretSignatureConfiguration);
        generator.setEncryptionConfiguration(secretEncryptionConfiguration);
        String token = "";
        // by default, as we are in a REST API controller, profiles are retrieved only in the request
        // here, we retrieve the profile from the session as we generate the token from a profile saved by an indirect client (from the UserInterfaceApplication)
        final Optional<UserProfile> profile = profileManager.getProfile();
        if (profile.isPresent()) {
            token = generator.generate(profile.get());
        }
        map.put("token", token);
        return "jwt";
    }

    @ExceptionHandler(HttpAction.class)
    public void httpAction() {
        // do nothing
    }
}
