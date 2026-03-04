import lombok.val;
import org.pac4j.core.config.properties.JwksProperties;
import org.pac4j.oidc.util.JwkHelper;

public class GenerateJwks {
    public static void main(String[] args) {
        val jwksProperties = new JwksProperties();
        jwksProperties.setJwksPath("file:/Users/jleleu/pac4jecosystem/spring-webmvc-pac4j-boot-demo/src/main/resources/static/ta/jwks.json");
        jwksProperties.setKid("ta-key-1");
        JwkHelper.loadCreateJwkFromJwks(jwksProperties);
    }
}
