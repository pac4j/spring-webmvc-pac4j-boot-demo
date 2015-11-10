package org.pac4j.demo.spring.controller;

import org.pac4j.cas.client.CasClient;
import org.pac4j.core.client.Clients;
import org.pac4j.core.config.Config;
import org.pac4j.core.context.J2EContext;
import org.pac4j.core.context.WebContext;
import org.pac4j.core.exception.RequiresHttpAction;
import org.pac4j.core.profile.ProfileManager;
import org.pac4j.core.profile.UserProfile;
import org.pac4j.http.client.indirect.FormClient;
import org.pac4j.http.client.indirect.IndirectBasicAuthClient;
import org.pac4j.jwt.profile.JwtGenerator;
import org.pac4j.oauth.client.FacebookClient;
import org.pac4j.oauth.client.TwitterClient;
import org.pac4j.oidc.client.OidcClient;
import org.pac4j.saml.client.SAML2Client;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Controller;
import org.springframework.web.bind.annotation.RequestMapping;

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.util.Map;

@Controller
public class Application {

    @Autowired
    private Config config;

    @Value("${salt}")
    private String salt;

    @RequestMapping("/")
    public String root(HttpServletRequest request, HttpServletResponse response, Map<String, Object> map) throws RequiresHttpAction {
        return index(request, response, map);
    }

    @RequestMapping("/index.html")
    public String index(HttpServletRequest request, HttpServletResponse response, Map<String, Object> map) throws RequiresHttpAction {
        final WebContext context = new J2EContext(request, response);
        map.put("profile", getStringProfile(context));
        final Clients clients = config.getClients();
        final FacebookClient fbClient = (FacebookClient) clients.findClient(context, "FacebookClient");
        final TwitterClient twClient = (TwitterClient) clients.findClient(context, "TwitterClient");
        final FormClient formClient = (FormClient) clients.findClient(context, "FormClient");
        final IndirectBasicAuthClient baClient = (IndirectBasicAuthClient) clients.findClient(context, "IndirectBasicAuthClient");
        final CasClient casClient = (CasClient) clients.findClient(context, "CasClient");
        final SAML2Client saml2Client = (SAML2Client) clients.findClient(context, "SAML2Client");
        final OidcClient oidcClient = (OidcClient) clients.findClient(context, "OidcClient");
        map.put("urlFacebook", (String) fbClient.getRedirectAction(context, false).getLocation());
        map.put("urlTwitter", (String) twClient.getRedirectAction(context, false).getLocation());
        map.put("urlForm", (String) formClient.getRedirectAction(context, false).getLocation());
        map.put("urlBasicAuth", (String) baClient.getRedirectAction(context, false).getLocation());
        map.put("urlCas", (String) casClient.getRedirectAction(context, false).getLocation());
        map.put("urlSaml", (String) saml2Client.getRedirectAction(context, false).getLocation());
        map.put("urlOidc", (String) oidcClient.getRedirectAction(context, false).getLocation());
        return "index";
    }

    private UserProfile getProfile(WebContext context) {
        final ProfileManager manager = new ProfileManager(context);
        return manager.get(true);
    }

    private String getStringProfile(WebContext context) {
        final UserProfile profile = getProfile(context);
        if (profile == null) {
            return "";
        } else {
            return profile.toString();
        }
    }

    @RequestMapping("/facebook/index.html")
    public String facebook(HttpServletRequest request, HttpServletResponse response, Map<String, Object> map) {
        return protectedIndex(request, response, map);
    }

    @RequestMapping("/facebook/notprotected.html")
    public String facebookNotProtected(HttpServletRequest request, HttpServletResponse response, Map<String, Object> map) {
        final WebContext context = new J2EContext(request, response);
        map.put("profile", getStringProfile(context));
        return "notProtected";
    }

    @RequestMapping("/facebookadmin/index.html")
    public String facebookadmin(HttpServletRequest request, HttpServletResponse response, Map<String, Object> map) {
        return protectedIndex(request, response, map);
    }

    @RequestMapping("/facebookcustom/index.html")
    public String facebookcustom(HttpServletRequest request, HttpServletResponse response, Map<String, Object> map) {
        return protectedIndex(request, response, map);
    }

    @RequestMapping("/twitter/index.html")
    public String twitter(HttpServletRequest request, HttpServletResponse response, Map<String, Object> map) {
        return protectedIndex(request, response, map);
    }

    @RequestMapping("/form/index.html")
    public String form(HttpServletRequest request, HttpServletResponse response, Map<String, Object> map) {
        return protectedIndex(request, response, map);
    }

    @RequestMapping("/basicauth/index.html")
    public String basicauth(HttpServletRequest request, HttpServletResponse response, Map<String, Object> map) {
        return protectedIndex(request, response, map);
    }

    @RequestMapping("/cas/index.html")
    public String cas(HttpServletRequest request, HttpServletResponse response, Map<String, Object> map) {
        return protectedIndex(request, response, map);
    }

    @RequestMapping("/saml/index.html")
    public String saml(HttpServletRequest request, HttpServletResponse response, Map<String, Object> map) {
        return protectedIndex(request, response, map);
    }

    @RequestMapping("/oidc/index.html")
    public String oidc(HttpServletRequest request, HttpServletResponse response, Map<String, Object> map) {
        return protectedIndex(request, response, map);
    }

    @RequestMapping("/protected/index.html")
    public String protect(HttpServletRequest request, HttpServletResponse response, Map<String, Object> map) {
        return protectedIndex(request, response, map);
    }

    @RequestMapping("/dba/index.html")
    public String dba(HttpServletRequest request, HttpServletResponse response, Map<String, Object> map) {
        return protectedIndex(request, response, map);
    }

    @RequestMapping("/rest-jwt/index.html")
    public String restJwt(HttpServletRequest request, HttpServletResponse response, Map<String, Object> map) {
        return protectedIndex(request, response, map);
    }

    @RequestMapping("/jwt.html")
    public String jwt(HttpServletRequest request, HttpServletResponse response, Map<String, Object> map) {
        final WebContext context = new J2EContext(request, response);
        final UserProfile profile = getProfile(context);
        final JwtGenerator generator = new JwtGenerator(salt);
        String token = "";
        if (profile != null) {
            token = generator.generate(profile);
        }
        map.put("token", token);
        return "jwt";
    }

    @RequestMapping("/theForm")
    public String theForm(HttpServletRequest request, HttpServletResponse response, Map<String, Object> map) {
        final WebContext context = new J2EContext(request, response);
        final FormClient formClient = (FormClient) config.getClients().findClient(context, "FormClient");
        map.put("callbackUrl", formClient.getCallbackUrl());
        return "form";
    }

    protected String protectedIndex(HttpServletRequest request, HttpServletResponse response, Map<String, Object> map) {
        final WebContext context = new J2EContext(request, response);
        map.put("profile", getStringProfile(context));
        return "protectedIndex";
    }
}
