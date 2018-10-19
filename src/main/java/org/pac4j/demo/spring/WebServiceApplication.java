package org.pac4j.demo.spring;

import org.pac4j.core.profile.CommonProfile;
import org.pac4j.jwt.config.encryption.SecretEncryptionConfiguration;
import org.pac4j.jwt.config.signature.SecretSignatureConfiguration;
import org.pac4j.jwt.profile.JwtGenerator;
import org.pac4j.springframework.helper.WSSecurityHelper;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Controller;
import org.springframework.web.bind.annotation.RequestMapping;

import java.util.Map;
import java.util.Optional;

@Controller
public class WebServiceApplication {

    @Value("${salt}")
    private String salt;

    @Autowired
    private WSSecurityHelper wsSecurityHelper;

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
        final Optional<CommonProfile> profile = wsSecurityHelper.getProfile(true);
        if (profile.isPresent()) {
            token = generator.generate(profile.get());
        }
        map.put("token", token);
        return "jwt";
    }

    protected String protectedIndex(final Map<String, Object> map) {
        map.put("profiles", wsSecurityHelper.getProfiles());
        return "protectedIndex";
    }
}
