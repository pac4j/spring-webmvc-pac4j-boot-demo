package org.pac4j.demo.spring;

import org.pac4j.core.client.Client;
import org.pac4j.core.config.Config;
import org.pac4j.core.context.J2EContext;
import org.pac4j.core.context.Pac4jConstants;
import org.pac4j.core.exception.HttpAction;
import org.pac4j.core.profile.CommonProfile;
import org.pac4j.core.profile.ProfileManager;
import org.pac4j.http.client.indirect.FormClient;
import org.pac4j.jwt.config.encryption.SecretEncryptionConfiguration;
import org.pac4j.jwt.config.signature.SecretSignatureConfiguration;
import org.pac4j.jwt.profile.JwtGenerator;
import org.pac4j.springframework.annotation.ui.RequireAnyRole;
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
    private J2EContext webContext;

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

    @RequestMapping("/index.html")
    public String index(final Map<String, Object> map) throws HttpAction {
        map.put("profiles", profileManager.getAll(true));
        map.put("sessionId", webContext.getSessionStore().getOrCreateSessionId(webContext));
        return "index";
    }

    @RequestMapping("/facebook/index.html")
    public String facebook(final Map<String, Object> map) {
        return protectedIndex(map);
    }

    @RequestMapping("/facebook/notprotected.html")
    public String facebookNotProtected(final Map<String, Object> map) {
        map.put("profiles", profileManager.getAll(true));
        return "notProtected";
    }

    @RequestMapping("/facebookadmin/index.html")
    @RequireAnyRole("ROLE_ADMIN")
    public String facebookadmin(final Map<String, Object> map) {
        return protectedIndex(map);
    }

    @RequestMapping("/facebookcustom/index.html")
    public String facebookcustom(final Map<String, Object> map) {
        return protectedIndex(map);
    }

    @RequestMapping("/twitter/index.html")
    public String twitter(final Map<String, Object> map) {
        return protectedIndex(map);
    }

    @RequestMapping("/form/index.html")
    public String form(final Map<String, Object> map) {
        return protectedIndex(map);
    }

    @RequestMapping("/basicauth/index.html")
    public String basicauth(final Map<String, Object> map) {
        return protectedIndex(map);
    }

    @RequestMapping("/cas/index.html")
    public String cas(final Map<String, Object> map) {
        return protectedIndex(map);
    }

    @RequestMapping("/saml/index.html")
    public String saml(final Map<String, Object> map) {
        return protectedIndex(map);
    }

    @RequestMapping("/oidc/index.html")
    public String oidc(final Map<String, Object> map) {
        return protectedIndex(map);
    }

    @RequestMapping("/protected/index.html")
    public String protect(final Map<String, Object> map) {
        return protectedIndex(map);
    }

    @RequestMapping("/loginForm")
    public String loginForm(final  Map<String, Object> map) {
        final FormClient formClient = (FormClient) config.getClients().findClient("FormClient");
        map.put("callbackUrl", formClient.getCallbackUrl());
        return "form";
    }

    @RequestMapping("/forceLogin")
    @ResponseBody
    public void forceLogin() {
        final Client client = config.getClients().findClient(webContext.getRequestParameter(Pac4jConstants.DEFAULT_CLIENT_NAME_PARAMETER));
        try {
            client.redirect(webContext);
        } catch (final HttpAction e) {
        }
    }

    protected String protectedIndex(final Map<String, Object> map) {
        map.put("profiles", profileManager.getAll(true));
        return "protectedIndex";
    }

    @RequestMapping("/centralLogout")
    @ResponseBody
    public void centralLogout() {
        logoutController.logout(webContext.getRequest(), webContext.getResponse());
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
        final Optional<CommonProfile> profile = profileManager.get(true);
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
