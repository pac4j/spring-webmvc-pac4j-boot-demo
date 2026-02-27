package org.pac4j.demo.spring;

import org.pac4j.core.authorization.authorizer.RequireAnyRoleAuthorizer;
import org.pac4j.core.config.Config;
import org.pac4j.springframework.annotation.AnnotationConfig;
import org.pac4j.springframework.component.ComponentConfig;
import org.pac4j.springframework.web.SecurityInterceptor;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.annotation.ComponentScan;
import org.springframework.context.annotation.Configuration;
import org.springframework.context.annotation.Import;
import org.springframework.web.servlet.config.annotation.InterceptorRegistry;
import org.springframework.web.servlet.config.annotation.WebMvcConfigurer;

@Configuration
@Import({ComponentConfig.class, AnnotationConfig.class})
@ComponentScan(basePackages = "org.pac4j.springframework.web")
public class SecurityConfig implements WebMvcConfigurer {

    @Autowired
    private Config config;

    @Override
    public void addInterceptors(InterceptorRegistry registry) {
        registry.addInterceptor(buildInterceptor("FacebookClient"))
            .addPathPatterns("/facebook/*")
            .excludePathPatterns("/facebook/notprotected.html");

        SecurityInterceptor interceptor = SecurityInterceptor.build(config,
            "FacebookClient", new RequireAnyRoleAuthorizer("ROLE_ADMIN"));

        registry.addInterceptor(interceptor).addPathPatterns("/facebookadmin/*");
        registry.addInterceptor(buildInterceptor("FacebookClient")).addPathPatterns("/facebookadmin/*");

        interceptor = SecurityInterceptor.build(config,
            "FacebookClient", new CustomAuthorizer());

        registry.addInterceptor(interceptor).addPathPatterns("/facebookcustom/*");
        registry.addInterceptor(buildInterceptor("TwitterClient,FacebookClient")).addPathPatterns("/twitter/*");
        registry.addInterceptor(buildInterceptor("FormClient")).addPathPatterns("/form/*");
        registry.addInterceptor(buildInterceptor("IndirectBasicAuthClient")).addPathPatterns("/basicauth/*");
        registry.addInterceptor(buildInterceptor("CasClient")).addPathPatterns("/cas/*");
        registry.addInterceptor(buildInterceptor("OidcClient")).addPathPatterns("/oidc/*");
        registry.addInterceptor(buildInterceptor("SAML2Client")).addPathPatterns("/saml/*");
        registry.addInterceptor(buildInterceptor("GoogleOidcClient")).addPathPatterns("/googleoidc/*");
        registry.addInterceptor(new SecurityInterceptor(config)).addPathPatterns("/protected/*");
        registry.addInterceptor(buildInterceptor("DirectBasicAuthClient,ParameterClient")).addPathPatterns("/dba/*");
        registry.addInterceptor(buildInterceptor("ParameterClient")).addPathPatterns("/rest-jwt/*");

        registry.addInterceptor(buildInterceptor("AnonymousClient")).addPathPatterns("/*").excludePathPatterns("/callback*");
    }

    private SecurityInterceptor buildInterceptor(final String client) {
        return SecurityInterceptor.build(config, client);
    }
}
