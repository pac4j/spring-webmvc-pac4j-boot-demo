package org.pac4j.demo.spring;

import org.pac4j.core.client.Client;
import org.pac4j.core.context.J2EContext;
import org.pac4j.core.context.Pac4jConstants;
import org.pac4j.core.exception.HttpAction;
import org.pac4j.http.client.indirect.FormClient;
import org.pac4j.springframework.controller.AbstractController;
import org.pac4j.springframework.web.LogoutController;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Controller;
import org.springframework.web.bind.annotation.ExceptionHandler;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.ResponseBody;

import javax.annotation.PostConstruct;

import java.util.Map;

@Controller
public class UserInterfaceApplication extends AbstractController {

    @Value("${pac4j.centralLogout.defaultUrl:#{null}}")
    private String defaultUrl;

    @Value("${pac4j.centralLogout.logoutUrlPattern:#{null}}")
    private String logoutUrlPattern;

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
        map.put("profiles", getProfiles());
        final J2EContext context = getJ2EContext();
        map.put("sessionId", context.getSessionStore().getOrCreateSessionId(context));
        return "index";
    }

    @RequestMapping("/facebook/index.html")
    public String facebook(final Map<String, Object> map) {
        return protectedIndex(map);
    }

    @RequestMapping("/facebook/notprotected.html")
    public String facebookNotProtected(final Map<String, Object> map) {
        map.put("profiles", getProfiles());
        return "notProtected";
    }

    @RequestMapping("/facebookadmin/index.html")
    public String facebookadmin(final Map<String, Object> map) {

        requireAnyRole("ROLE_ADMIN");

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
        final Client client = config.getClients().findClient(request.getParameter(Pac4jConstants.DEFAULT_CLIENT_NAME_PARAMETER));
        try {
            client.redirect(getJ2EContext());
        } catch (final HttpAction e) {
        }
    }

    protected String protectedIndex(final Map<String, Object> map) {
        map.put("profiles", getProfiles());
        return "protectedIndex";
    }

    @RequestMapping("/centralLogout")
    public void centralLogout() {
        logoutController.logout(request, response);
    }

    @ExceptionHandler(HttpAction.class)
    public void httpAction() {
        // do nothing
    }
}
