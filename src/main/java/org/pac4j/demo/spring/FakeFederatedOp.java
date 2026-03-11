package org.pac4j.demo.spring;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.nimbusds.jose.jwk.JWK;
import com.nimbusds.jose.jwk.JWKSet;
import com.nimbusds.jwt.JWTClaimsSet;
import lombok.val;
import org.pac4j.core.config.properties.JwksProperties;
import org.pac4j.core.util.JwkHelper;
import org.pac4j.oidc.federation.entity.DefaultEntityConfigurationGenerator;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.core.io.ClassPathResource;
import org.springframework.stereotype.Controller;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.ResponseBody;

import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.text.ParseException;
import java.util.Date;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

@Controller
public class FakeFederatedOp {

    public static final String TYPE = DefaultEntityConfigurationGenerator.CONTENT_TYPE;
    //private static final String TYPE = MediaType.APPLICATION_JSON_VALUE;

    @Value("${server.port:8080}")
    private String serverPort;

    @RequestMapping(value = "/op/register", produces = TYPE)
    @ResponseBody
    public String registerClient() throws Exception {
        val opRegister = getStaticFile("op/register.json");
        val jsonConfig = new ObjectMapper().readValue(opRegister, Map.class);

        val opKey = loadKey("op/keystore.jwks", "cas-qGcosGMN");

        val claims = JWTClaimsSet.parse(jsonConfig);
        return JwkHelper.buildSignedJwt(claims, opKey, DefaultEntityConfigurationGenerator.ENTITY_STATEMENT_TYPE);
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
        return JwkHelper.loadJwkFromOrCreateJwks(jwksProperties);
    }

    private String getStaticFile(final String name) throws IOException {
        val rsc = new ClassPathResource("static/" + name);
        val inputStream = rsc.getInputStream();
        val originalBytes = inputStream.readAllBytes();
        inputStream.close();
        val json = new String(originalBytes, StandardCharsets.UTF_8);
        return json.replace("$PORT", serverPort);
    }
}
