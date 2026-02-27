package org.pac4j.demo.spring;

import lombok.val;
import org.pac4j.core.client.Client;
import org.pac4j.core.config.Config;
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
import org.pac4j.springframework.annotation.RequireAnyRole;
import org.pac4j.springframework.web.LogoutController;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Controller;
import org.springframework.web.bind.annotation.ExceptionHandler;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.ResponseBody;

import javax.annotation.PostConstruct;
import java.util.Map;
import java.util.Optional;

@Controller
public class Application {

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

    @RequestMapping("/")
    public String root(final Map<String, Object> map) throws HttpAction {
        return index(map);
    }

    @RequestMapping(value = "/.well-known/openid-federation") //, produces = DefaultEntityConfigurationGenerator.CONTENT_TYPE)
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
