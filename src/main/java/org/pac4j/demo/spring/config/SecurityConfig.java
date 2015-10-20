package org.pac4j.demo.spring.config;

import org.pac4j.core.config.Config;
import org.pac4j.springframework.web.RequiresAuthenticationInterceptor;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.annotation.ComponentScan;
import org.springframework.context.annotation.Configuration;
import org.springframework.web.servlet.config.annotation.InterceptorRegistry;
import org.springframework.web.servlet.config.annotation.WebMvcConfigurerAdapter;

@Configuration
@ComponentScan(basePackages = "org.pac4j.springframework.web")
public class SecurityConfig extends WebMvcConfigurerAdapter {

    @Autowired
    private Config config;

    @Override
    public void addInterceptors(InterceptorRegistry registry) {
        registry.addInterceptor(new RequiresAuthenticationInterceptor(config, "FacebookClient")).addPathPatterns("/facebook/*").excludePathPatterns("/facebook/notprotected.html");
        registry.addInterceptor(new RequiresAuthenticationInterceptor(config, "FacebookClient", "admin")).addPathPatterns("/facebookadmin/*");
        registry.addInterceptor(new RequiresAuthenticationInterceptor(config, "FacebookClient", "custom")).addPathPatterns("/facebookcustom/*");
        registry.addInterceptor(new RequiresAuthenticationInterceptor(config, "TwitterClient,FacebookClient")).addPathPatterns("/twitter/*");
        registry.addInterceptor(new RequiresAuthenticationInterceptor(config, "FormClient")).addPathPatterns("/form/*");
        registry.addInterceptor(new RequiresAuthenticationInterceptor(config, "IndirectBasicAuthClient")).addPathPatterns("/basicauth/*");
        registry.addInterceptor(new RequiresAuthenticationInterceptor(config, "CasClient")).addPathPatterns("/cas/*");
        registry.addInterceptor(new RequiresAuthenticationInterceptor(config, "SAML2Client")).addPathPatterns("/saml/*");
        registry.addInterceptor(new RequiresAuthenticationInterceptor(config, "OidcClient")).addPathPatterns("/oidc/*");
        registry.addInterceptor(new RequiresAuthenticationInterceptor(config)).addPathPatterns("/protected/*");
        registry.addInterceptor(new RequiresAuthenticationInterceptor(config, "DirectBasicAuthClient,ParameterClient")).addPathPatterns("/dba/*");
        registry.addInterceptor(new RequiresAuthenticationInterceptor(config, "ParameterClient")).addPathPatterns("/rest-jwt/*");
    }
}
