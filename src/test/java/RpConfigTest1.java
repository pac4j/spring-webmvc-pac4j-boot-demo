import com.nimbusds.jose.JWSAlgorithm;
import lombok.val;
import org.pac4j.oidc.config.OidcConfiguration;

import static org.pac4j.demo.spring.Pac4jConfig.OIDC_ENV;

public class RpConfigTest1 {

    public static void main(String[] args) {
        val config = new OidcConfiguration();
        config.setDiscoveryURI("https://" + OIDC_ENV + ".certification.openid.net/test/a/rppac4jbas/.well-known/openid-configuration");
        config.setClientId("myclient");
        config.setSecret("mysecret");
        config.setUseNonce(true);
        config.setIdTokenSigningAlgorithm(JWSAlgorithm.RS256);

        config.init();

        for (int i = 0; i < 100; i++) {
            config.getOpMetadataResolver().load();
        }
    }
}
