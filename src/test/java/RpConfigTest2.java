import com.nimbusds.jose.JWSAlgorithm;
import com.nimbusds.jwt.SignedJWT;
import com.nimbusds.openid.connect.sdk.Nonce;
import lombok.val;
import org.pac4j.oidc.config.OidcConfiguration;

import static org.pac4j.demo.spring.Pac4jConfig.OIDC_ENV;

public class RpConfigTest2 {

    public static void main(String[] args) throws Exception {
        val config = new OidcConfiguration();
        config.setDiscoveryURI("https://" + OIDC_ENV + ".certification.openid.net/test/a/rppac4jbas/.well-known/openid-configuration");
        config.setClientId("myclient");
        config.setSecret("mysecret");
        config.setUseNonce(true);
        config.setIdTokenSigningAlgorithm(JWSAlgorithm.RS256);

        config.init();

        val validator = config.getOpMetadataResolver().getTokenValidator();
        val jwt = SignedJWT.parse("eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCIsImtpZCI6ImFrZXkifQ.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiYWRtaW4iOnRydWUsImlhdCI6MTUxNjIzOTAyMn0.T4j5g7G9gHYVLA5wbXMU-cExg7WOimQRH85vvmMWoFKrxB1DbLwGItmrv-WQkWUPg8XIXTbWY8dqPRsdLD4AIx07RCdl0JrfCJkVu-88jA6Ljr3saBXzn3gH1vYnw-GX4IcXV-iwMnayc98u8WTsd1MA_JIm7ssdN5T5wVXLRAUGkha85dwPjC9naFhA282p_siWtutWilyOv7u27pAg7ubJj5NRmoqLSJNXtv6KT5vkvUmtVZANQ7eALRMnztHuXJHhg_6KikCETWp02JaHajAm9Zlm4PrQq765c60OK6xeyBiv5IDhHv6TO5XbsImDBnFJnCqfH-MHQMbsU5np_Q");
        validator.validateIdToken(jwt, new Nonce());
    }
}
