import com.fasterxml.jackson.databind.ObjectMapper;
import com.nimbusds.jose.jwk.JWK;
import com.nimbusds.jose.jwk.JWKSet;
import com.nimbusds.jwt.SignedJWT;
import com.nimbusds.jwt.JWTClaimsSet;
import lombok.val;
import org.pac4j.core.config.properties.JwksProperties;
import org.pac4j.core.util.JwkHelper;
import org.pac4j.oidc.federation.entity.DefaultEntityConfigurationGenerator;

import java.net.URI;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.util.Date;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.UUID;

public class TrustAnchorGenerator {
    private static final String RP_BASE_URL = "http://localhost:8081";
    private static final String TRUST_ANCHOR_URL = RP_BASE_URL + "/trustanchor";
    private static final String OP_WELL_KNOWN_URL = "http://127.0.0.1:8080/c2id/.well-known/openid-configuration";
    private static final String OP_ENTITY_ID = "http://127.0.0.1:8080/c2id";
    private static final String OP_FEDERATION_WELL_KNOWN_URL = OP_ENTITY_ID + "/.well-known/openid-federation";
    private static final String RP_FEDERATION_WELL_KNOWN_URL = RP_BASE_URL + "/.well-known/openid-federation";
    private static final String TA_JWKS_CLASSPATH = "classpath:static/ta/jwks.json";
    private static final String TA_KEY_ID = "ta-key-1";

    public static void main(String[] args) throws Exception {
        val taKey = loadTaKey();
        val taPublicJwks = new JWKSet(taKey.toPublicJWK()).toString(false);
        val opFederation = fetchFederationStatement(OP_FEDERATION_WELL_KNOWN_URL);
        val rpFederation = fetchFederationStatement(RP_FEDERATION_WELL_KNOWN_URL);
        val opConfig = fetchJson(OP_WELL_KNOWN_URL);
        val trustAnchorEntityStatement = generateTrustAnchorEntityStatement(taKey);
        val fetchEntityStatementForOp = generateFetchEntityStatementForOp(taKey, opConfig, opFederation.jwks());
        val fetchEntityStatementForRp = generateFetchEntityStatementForRp(taKey, rpFederation.metadata(), rpFederation.jwks());
        System.out.println("=== Trust Anchor JWKS (/trustanchor/jwks.json) ===");
        System.out.println(taPublicJwks);
        System.out.println();

        System.out.println("=== Trust Anchor Entity Statement (/trustanchor/.well-known/openid-federation) ===");
        System.out.println(trustAnchorEntityStatement);
        System.out.println();
        System.out.println("=== Trust Anchor Fetch Entity Statement (/trustanchor/fetch) for OP sub=" + OP_ENTITY_ID + " ===");
        System.out.println(fetchEntityStatementForOp);
        System.out.println();
        System.out.println("=== Trust Anchor Fetch Entity Statement (/trustanchor/fetch) for RP sub=" + RP_BASE_URL + " ===");
        System.out.println(fetchEntityStatementForRp);
    }

    private static String generateTrustAnchorEntityStatement(final JWK taKey) {
        val publicTa = taKey.toPublicJWK();
        val claims = baseClaims(TRUST_ANCHOR_URL, TRUST_ANCHOR_URL)
            .claim("metadata", buildTrustAnchorMetadata())
            .claim("jwks", new JWKSet(publicTa).toJSONObject())
            .claim("supported_subordinates", List.of(OP_ENTITY_ID, RP_BASE_URL))
            .build();

        return JwkHelper.buildSignedJwt(claims, taKey, DefaultEntityConfigurationGenerator.ENTITY_STATEMENT_TYPE);
    }

    private static String generateFetchEntityStatementForOp(final JWK taKey, final LinkedHashMap<String, Object> opConfig, final JWKSet opFederationJwks) {
        val openidProviderMetadata = new LinkedHashMap<String, Object>(opConfig);
        if (!openidProviderMetadata.containsKey("client_registration_types_supported")) {
            openidProviderMetadata.put("client_registration_types_supported", List.of("automatic", "explicit"));
        }

        val metadata = new LinkedHashMap<String, Object>();
        metadata.put("openid_provider", openidProviderMetadata);

        val claims = baseClaims(TRUST_ANCHOR_URL, OP_ENTITY_ID)
            .claim("metadata", metadata)
            .claim("jwks", opFederationJwks.toJSONObject())
            .claim("authority_hints", List.of(TRUST_ANCHOR_URL))
            .build();

        return JwkHelper.buildSignedJwt(claims, taKey, DefaultEntityConfigurationGenerator.ENTITY_STATEMENT_TYPE);
    }

    private static String generateFetchEntityStatementForRp(final JWK taKey, final Map<String, Object> rpMetadata, final JWKSet rpFederationJwks) {
        val metadata = new LinkedHashMap<String, Object>(rpMetadata);
        val claims = baseClaims(TRUST_ANCHOR_URL, RP_BASE_URL)
            .claim("metadata", metadata)
            .claim("jwks", rpFederationJwks.toJSONObject())
            .claim("authority_hints", List.of(TRUST_ANCHOR_URL))
            .build();
        return JwkHelper.buildSignedJwt(claims, taKey, DefaultEntityConfigurationGenerator.ENTITY_STATEMENT_TYPE);
    }

    private static LinkedHashMap<String, Object> buildTrustAnchorMetadata() {
        val federationEntity = new LinkedHashMap<String, Object>();
        federationEntity.put("federation_fetch_endpoint", TRUST_ANCHOR_URL + "/fetch");
        federationEntity.put("federation_list_endpoint", TRUST_ANCHOR_URL + "/list");
        federationEntity.put("federation_resolve_endpoint", TRUST_ANCHOR_URL + "/resolve");

        val metadata = new LinkedHashMap<String, Object>();
        metadata.put("federation_entity", federationEntity);
        return metadata;
    }

    private static JWTClaimsSet.Builder baseClaims(final String issuer, final String subject) {
        val now = new Date();
        val validityMs = 365L * 24 * 60 * 60 * 1000;
        val exp = new Date(now.getTime() + validityMs);
        return new JWTClaimsSet.Builder()
            .issuer(issuer)
            .subject(subject)
            .jwtID(UUID.randomUUID().toString())
            .issueTime(now)
            .expirationTime(exp)
            .notBeforeTime(now);
    }

    @SuppressWarnings("unchecked")
    private static FederationData fetchFederationStatement(final String url) throws Exception {
        val esJwt = fetchString(url);
        val signedJwt = SignedJWT.parse(esJwt);
        val claims = signedJwt.getJWTClaimsSet();
        val metadataClaim = claims.getJSONObjectClaim("metadata");
        if (metadataClaim == null) {
            throw new IllegalStateException("metadata claim is missing in federation entity statement: " + url);
        }
        val jwksClaim = claims.getJSONObjectClaim("jwks");
        if (jwksClaim == null) {
            throw new IllegalStateException("jwks claim is missing in federation entity statement: " + url);
        }
        return new FederationData(esJwt, new LinkedHashMap<>(metadataClaim), JWKSet.parse(jwksClaim));
    }

    private static JWK loadTaKey() {
        val jwksProperties = new JwksProperties();
        jwksProperties.setJwksPath(TA_JWKS_CLASSPATH);
        jwksProperties.setKid(TA_KEY_ID);
        return JwkHelper.loadJwkFromOrCreateJwks(jwksProperties);
    }

    @SuppressWarnings("unchecked")
    private static LinkedHashMap<String, Object> fetchJson(final String url) throws Exception {
        return new ObjectMapper().readValue(fetchString(url), LinkedHashMap.class);
    }

    private static String fetchString(final String url) throws Exception {
        val client = HttpClient.newHttpClient();
        val request = HttpRequest.newBuilder()
            .uri(URI.create(url))
            .GET()
            .build();
        val response = client.send(request, HttpResponse.BodyHandlers.ofString());
        if (response.statusCode() < 200 || response.statusCode() >= 300) {
            throw new IllegalStateException("Cannot load URL " + url + " [" + response.statusCode() + "]");
        }
        return response.body();
    }

    private record FederationData(String entityStatement, Map<String, Object> metadata, JWKSet jwks) {
    }
}
