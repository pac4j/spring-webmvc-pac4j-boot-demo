import lombok.val;
import org.pac4j.core.config.properties.JwksProperties;
import org.pac4j.core.util.JwkHelper;

public class GeneratePublicRpJwks {
    public static void main(String[] args) {
        val jwksProperties = new JwksProperties();
        jwksProperties.setJwksPath("file:/Users/jleleu/pac4jecosystem/spring-webmvc-pac4j-boot-demo/metadata/rpjwks.jwks");
        jwksProperties.setKid("defaultjwks0326");
        val key = JwkHelper.loadJwkFromOrCreateJwks(jwksProperties);
        JwkHelper.saveJwkPublic(key, "/Users/jleleu/pac4jecosystem/spring-webmvc-pac4j-boot-demo/metadata/rpjwks-public.jwks");
    }
}
