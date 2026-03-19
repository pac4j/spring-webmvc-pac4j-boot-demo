package org.pac4j.demo.spring;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.nimbusds.jose.jwk.JWK;
import com.nimbusds.jose.jwk.JWKSet;
import com.nimbusds.jwt.JWTClaimsSet;
import jakarta.servlet.http.HttpServletRequest;
import lombok.val;
import org.pac4j.core.config.properties.JwksProperties;
import org.pac4j.core.util.JwkHelper;
import org.pac4j.oidc.federation.entity.DefaultEntityConfigurationGenerator;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.core.io.ClassPathResource;
import org.springframework.stereotype.Controller;
import org.springframework.web.bind.annotation.GetMapping;
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
public class FakeFederation {

    public static final String TYPE = DefaultEntityConfigurationGenerator.CONTENT_TYPE;
    //private static final String TYPE = MediaType.APPLICATION_JSON_VALUE;

    @Value("${server.port:8080}")
    private String serverPort;

    @GetMapping(value = "/trustanchor/.well-known/openid-federation", produces = TYPE)
    @ResponseBody
    public String trustAnchorWellKnown() throws Exception {
        return "eyJraWQiOiJ0YS1rZXktMSIsInR5cCI6ImVudGl0eS1zdGF0ZW1lbnQrand0IiwiYWxnIjoiUlMyNTYifQ.eyJzdWIiOiJodHRwOi8vbG9jYWxob3N0OjgwODEvdHJ1c3RhbmNob3IiLCJtZXRhZGF0YSI6eyJmZWRlcmF0aW9uX2VudGl0eSI6eyJmZWRlcmF0aW9uX2ZldGNoX2VuZHBvaW50IjoiaHR0cDovL2xvY2FsaG9zdDo4MDgxL3RydXN0YW5jaG9yL2ZldGNoIiwiZmVkZXJhdGlvbl9saXN0X2VuZHBvaW50IjoiaHR0cDovL2xvY2FsaG9zdDo4MDgxL3RydXN0YW5jaG9yL2xpc3QiLCJmZWRlcmF0aW9uX3Jlc29sdmVfZW5kcG9pbnQiOiJodHRwOi8vbG9jYWxob3N0OjgwODEvdHJ1c3RhbmNob3IvcmVzb2x2ZSJ9fSwibmJmIjoxNzczOTUwNTAzLCJqd2tzIjp7ImtleXMiOlt7Imt0eSI6IlJTQSIsImUiOiJBUUFCIiwidXNlIjoic2lnIiwia2lkIjoidGEta2V5LTEiLCJuIjoieVo3T0F2OFVmYWQyQjM3V0NDMy1mOS10dDZJNkYwcUhjTHpERmV2NmtjSEdUUnRhYV9vMlJrUTg3VWVpQUk5T2hDUUJBdXFnRmdDN2lUZXpOZlVnaWtCUnEydVFlRjZMa2JpQVROb29fWXF6VEJDdG01VlJqbEt4SUNQLVJ1eDZMNy0xUVcxVEJPbmQxTGp1NmRnZE9QNUVIaEhuYUNHVnkyb1p3NHNWR2xtOTROWXBYVXBzU05NTUFCbTRBX3l3NU12STRpMDBidXh2ZE5Nd2xDN24zYjNxQ1hfR3FFaTdXMkVrb0FlTkNzQTc4UGwwcFZieFNPZUI4OWVoeU9IVzVtcmI4Y1pKYzZVTjFxZVRaNl9mdnRKSkwzZkFZY2VnSjU5eDlPZ1RKRFR4eE9ZeWxjeVE5aUVwZURHdkU5SE9kRUlqQVYtVmlRdGNOVTVUUlFuZUR3In1dfSwic3VwcG9ydGVkX3N1Ym9yZGluYXRlcyI6WyJodHRwOi8vMTI3LjAuMC4xOjgwODAvYzJpZCIsImh0dHA6Ly9sb2NhbGhvc3Q6ODA4MSJdLCJpc3MiOiJodHRwOi8vbG9jYWxob3N0OjgwODEvdHJ1c3RhbmNob3IiLCJleHAiOjE4MDU0ODY1MDMsImlhdCI6MTc3Mzk1MDUwMywianRpIjoiM2NiNGI5ODItYWVhOC00YmQwLTlmN2EtNjA5NzE0YjljZGExIn0.FJOpgQyyq4wxM4JWjirhLXNM5ysR7vXiV77mLCKzF9jJdOTyimlfzvXRjEKCbNMq8YwldcoAfArKDYtI4eHb1BZUp5aYAojjx9nUNaQe7eezGUpT0jSSR_oNhcfmVucTpQ5hDFlgn8EtBAl7RHRhuO75VpqmGSnEHjlRPCjSBNBwoo9_NepNiebWrSjIHzyVwUTIeW3-ZbHleJDSRYmxOnzcoEb4qhlxtZDmZtc8P29aE99uIujb-rlrNb0kOmzbp82OfOflt5FyAmaLHK9Rirs_bneYLCoI9kLN4EIPOnCJ046FbaB31GKAJdG7N4vBabK4L897BynKoyihoUHj4Q";
    }

    @GetMapping(value = "/trustanchor/fetch", produces = TYPE)
    @ResponseBody
    public String trustAnchorFetch(final HttpServletRequest request) throws Exception {
        val sub = request.getParameter("sub");
        if (sub.contains("127.0.0.1")) { // OP
            return "eyJraWQiOiJ0YS1rZXktMSIsInR5cCI6ImVudGl0eS1zdGF0ZW1lbnQrand0IiwiYWxnIjoiUlMyNTYifQ.eyJzdWIiOiJodHRwOi8vMTI3LjAuMC4xOjgwODAvYzJpZCIsIm1ldGFkYXRhIjp7Im9wZW5pZF9wcm92aWRlciI6eyJhdXRob3JpemF0aW9uX2VuZHBvaW50IjoiaHR0cDovLzEyNy4wLjAuMTo4MDgwL2MyaWQtbG9naW4iLCJ0b2tlbl9lbmRwb2ludCI6Imh0dHA6Ly8xMjcuMC4wLjE6ODA4MC9jMmlkL3Rva2VuIiwicmVnaXN0cmF0aW9uX2VuZHBvaW50IjoiaHR0cDovLzEyNy4wLjAuMTo4MDgwL2MyaWQvY2xpZW50cyIsImludHJvc3BlY3Rpb25fZW5kcG9pbnQiOiJodHRwOi8vMTI3LjAuMC4xOjgwODAvYzJpZC90b2tlbi9pbnRyb3NwZWN0IiwicmV2b2NhdGlvbl9lbmRwb2ludCI6Imh0dHA6Ly8xMjcuMC4wLjE6ODA4MC9jMmlkL3Rva2VuL3Jldm9rZSIsInB1c2hlZF9hdXRob3JpemF0aW9uX3JlcXVlc3RfZW5kcG9pbnQiOiJodHRwOi8vMTI3LjAuMC4xOjgwODAvYzJpZC9wYXIiLCJpc3N1ZXIiOiJodHRwOi8vMTI3LjAuMC4xOjgwODAvYzJpZCIsImp3a3NfdXJpIjoiaHR0cDovLzEyNy4wLjAuMTo4MDgwL2MyaWQvandrcy5qc29uIiwic2NvcGVzX3N1cHBvcnRlZCI6WyJvcGVuaWQiXSwicmVzcG9uc2VfdHlwZXNfc3VwcG9ydGVkIjpbImNvZGUiLCJ0b2tlbiIsImlkX3Rva2VuIiwiaWRfdG9rZW4gdG9rZW4iLCJjb2RlIGlkX3Rva2VuIiwiY29kZSBpZF90b2tlbiB0b2tlbiJdLCJyZXNwb25zZV9tb2Rlc19zdXBwb3J0ZWQiOlsicXVlcnkiLCJmcmFnbWVudCIsImZvcm1fcG9zdCIsInF1ZXJ5Lmp3dCIsImZyYWdtZW50Lmp3dCIsImZvcm1fcG9zdC5qd3QiLCJqd3QiXSwiZ3JhbnRfdHlwZXNfc3VwcG9ydGVkIjpbImltcGxpY2l0IiwiYXV0aG9yaXphdGlvbl9jb2RlIiwicmVmcmVzaF90b2tlbiIsInBhc3N3b3JkIiwiY2xpZW50X2NyZWRlbnRpYWxzIiwidXJuOmlldGY6cGFyYW1zOm9hdXRoOmdyYW50LXR5cGU6and0LWJlYXJlciJdLCJjb2RlX2NoYWxsZW5nZV9tZXRob2RzX3N1cHBvcnRlZCI6WyJwbGFpbiIsIlMyNTYiXSwidG9rZW5fZW5kcG9pbnRfYXV0aF9tZXRob2RzX3N1cHBvcnRlZCI6WyJjbGllbnRfc2VjcmV0X2Jhc2ljIiwiY2xpZW50X3NlY3JldF9wb3N0IiwiY2xpZW50X3NlY3JldF9qd3QiLCJwcml2YXRlX2tleV9qd3QiLCJub25lIl0sInRva2VuX2VuZHBvaW50X2F1dGhfc2lnbmluZ19hbGdfdmFsdWVzX3N1cHBvcnRlZCI6WyJIUzI1NiIsIkhTMzg0IiwiSFM1MTIiLCJSUzI1NiIsIlJTMzg0IiwiUlM1MTIiLCJQUzI1NiIsIlBTMzg0IiwiUFM1MTIiLCJFUzI1NiIsIkVTMjU2SyIsIkVTMzg0IiwiRVM1MTIiXSwicmVxdWVzdF9vYmplY3Rfc2lnbmluZ19hbGdfdmFsdWVzX3N1cHBvcnRlZCI6WyJIUzI1NiIsIkhTMzg0IiwiSFM1MTIiLCJSUzI1NiIsIlJTMzg0IiwiUlM1MTIiLCJQUzI1NiIsIlBTMzg0IiwiUFM1MTIiLCJFUzI1NiIsIkVTMjU2SyIsIkVTMzg0IiwiRVM1MTIiXSwicmVxdWVzdF9vYmplY3RfZW5jcnlwdGlvbl9hbGdfdmFsdWVzX3N1cHBvcnRlZCI6WyJSU0EtT0FFUC0yNTYiLCJSU0EtT0FFUC0zODQiLCJSU0EtT0FFUC01MTIiLCJFQ0RILUVTIiwiRUNESC1FUytBMTI4S1ciLCJFQ0RILUVTK0ExOTJLVyIsIkVDREgtRVMrQTI1NktXIiwiZGlyIl0sInJlcXVlc3Rfb2JqZWN0X2VuY3J5cHRpb25fZW5jX3ZhbHVlc19zdXBwb3J0ZWQiOlsiQTEyOENCQy1IUzI1NiIsIkExOTJDQkMtSFMzODQiLCJBMjU2Q0JDLUhTNTEyIiwiQTEyOEdDTSIsIkExOTJHQ00iLCJBMjU2R0NNIiwiWEMyMFAiXSwicmVxdWVzdF9wYXJhbWV0ZXJfc3VwcG9ydGVkIjp0cnVlLCJyZXF1ZXN0X3VyaV9wYXJhbWV0ZXJfc3VwcG9ydGVkIjp0cnVlLCJyZXF1aXJlX3JlcXVlc3RfdXJpX3JlZ2lzdHJhdGlvbiI6dHJ1ZSwiYXV0aG9yaXphdGlvbl9yZXNwb25zZV9pc3NfcGFyYW1ldGVyX3N1cHBvcnRlZCI6dHJ1ZSwidGxzX2NsaWVudF9jZXJ0aWZpY2F0ZV9ib3VuZF9hY2Nlc3NfdG9rZW5zIjp0cnVlLCJkcG9wX3NpZ25pbmdfYWxnX3ZhbHVlc19zdXBwb3J0ZWQiOlsiRVMyNTZLIiwiUFMzODQiLCJFUzM4NCIsIlJTMzg0IiwiRVMyNTYiLCJSUzI1NiIsIkVTNTEyIiwiUFMyNTYiLCJQUzUxMiIsIlJTNTEyIl0sImF1dGhvcml6YXRpb25fc2lnbmluZ19hbGdfdmFsdWVzX3N1cHBvcnRlZCI6WyJIUzI1NiIsIkhTMzg0IiwiSFM1MTIiLCJSUzI1NiIsIlJTMzg0IiwiUlM1MTIiLCJQUzI1NiIsIlBTMzg0IiwiUFM1MTIiLCJFUzI1NiIsIkVTMjU2SyIsIkVTMzg0IiwiRVM1MTIiLCJFZERTQSJdLCJhdXRob3JpemF0aW9uX2VuY3J5cHRpb25fYWxnX3ZhbHVlc19zdXBwb3J0ZWQiOlsiUlNBLU9BRVAtMjU2IiwiUlNBLU9BRVAtMzg0IiwiUlNBLU9BRVAtNTEyIiwiRUNESC1FUyIsIkVDREgtRVMrQTEyOEtXIiwiRUNESC1FUytBMTkyS1ciLCJFQ0RILUVTK0EyNTZLVyIsImRpciJdLCJhdXRob3JpemF0aW9uX2VuY3J5cHRpb25fZW5jX3ZhbHVlc19zdXBwb3J0ZWQiOlsiQTEyOENCQy1IUzI1NiIsIkExOTJDQkMtSFMzODQiLCJBMjU2Q0JDLUhTNTEyIiwiQTEyOEdDTSIsIkExOTJHQ00iLCJBMjU2R0NNIiwiWEMyMFAiXSwicHJvbXB0X3ZhbHVlc19zdXBwb3J0ZWQiOlsiY29uc2VudCIsInNlbGVjdF9hY2NvdW50IiwiY3JlYXRlIiwibG9naW4iLCJub25lIl0sIm9yZ2FuaXphdGlvbl9uYW1lIjoicGFjNGpfdGVzdF9jMmlkIiwic2lnbmVkX2p3a3NfdXJpIjoiaHR0cDovLzEyNy4wLjAuMTo4MDgwL2MyaWQvandrcy5qd3QiLCJjbGllbnRfcmVnaXN0cmF0aW9uX3R5cGVzX3N1cHBvcnRlZCI6WyJhdXRvbWF0aWMiXSwicmVxdWVzdF9hdXRoZW50aWNhdGlvbl9tZXRob2RzX3N1cHBvcnRlZCI6eyJwdXNoZWRfYXV0aG9yaXphdGlvbl9yZXF1ZXN0X2VuZHBvaW50IjpbInByaXZhdGVfa2V5X2p3dCIsInRsc19jbGllbnRfYXV0aCIsInNlbGZfc2lnbmVkX3Rsc19jbGllbnRfYXV0aCJdLCJhdXRob3JpemF0aW9uX2VuZHBvaW50IjpbInJlcXVlc3Rfb2JqZWN0Il19LCJyZXF1ZXN0X3VyaV9xdW90YSI6MTAsInN1YmplY3RfdHlwZXNfc3VwcG9ydGVkIjpbInB1YmxpYyIsInBhaXJ3aXNlIl0sInVzZXJpbmZvX2VuZHBvaW50IjoiaHR0cDovLzEyNy4wLjAuMTo4MDgwL2MyaWQvdXNlcmluZm8iLCJpZF90b2tlbl9zaWduaW5nX2FsZ192YWx1ZXNfc3VwcG9ydGVkIjpbIlJTMjU2IiwiUlMzODQiLCJSUzUxMiIsIlBTMjU2IiwiUFMzODQiLCJQUzUxMiIsIkVTMjU2IiwiRVMyNTZLIiwiRVMzODQiLCJFUzUxMiIsIkhTMjU2IiwiSFMzODQiLCJIUzUxMiIsIkVkRFNBIl0sImlkX3Rva2VuX2VuY3J5cHRpb25fYWxnX3ZhbHVlc19zdXBwb3J0ZWQiOlsiUlNBLU9BRVAtMjU2IiwiUlNBLU9BRVAtMzg0IiwiUlNBLU9BRVAtNTEyIiwiRUNESC1FUyIsIkVDREgtRVMrQTEyOEtXIiwiRUNESC1FUytBMTkyS1ciLCJFQ0RILUVTK0EyNTZLVyIsImRpciIsIkExMjhLVyIsIkExOTJLVyIsIkEyNTZLVyIsIkExMjhHQ01LVyIsIkExOTJHQ01LVyIsIkEyNTZHQ01LVyJdLCJpZF90b2tlbl9lbmNyeXB0aW9uX2VuY192YWx1ZXNfc3VwcG9ydGVkIjpbIkExMjhDQkMtSFMyNTYiLCJBMTkyQ0JDLUhTMzg0IiwiQTI1NkNCQy1IUzUxMiIsIkExMjhHQ00iLCJBMTkyR0NNIiwiQTI1NkdDTSIsIlhDMjBQIl0sInVzZXJpbmZvX3NpZ25pbmdfYWxnX3ZhbHVlc19zdXBwb3J0ZWQiOlsiUlMyNTYiLCJSUzM4NCIsIlJTNTEyIiwiUFMyNTYiLCJQUzM4NCIsIlBTNTEyIiwiRVMyNTYiLCJFUzI1NksiLCJFUzM4NCIsIkVTNTEyIiwiSFMyNTYiLCJIUzM4NCIsIkhTNTEyIiwiRWREU0EiXSwidXNlcmluZm9fZW5jcnlwdGlvbl9hbGdfdmFsdWVzX3N1cHBvcnRlZCI6WyJSU0EtT0FFUC0yNTYiLCJSU0EtT0FFUC0zODQiLCJSU0EtT0FFUC01MTIiLCJFQ0RILUVTIiwiRUNESC1FUytBMTI4S1ciLCJFQ0RILUVTK0ExOTJLVyIsIkVDREgtRVMrQTI1NktXIiwiZGlyIiwiQTEyOEtXIiwiQTE5MktXIiwiQTI1NktXIiwiQTEyOEdDTUtXIiwiQTE5MkdDTUtXIiwiQTI1NkdDTUtXIl0sInVzZXJpbmZvX2VuY3J5cHRpb25fZW5jX3ZhbHVlc19zdXBwb3J0ZWQiOlsiQTEyOENCQy1IUzI1NiIsIkExOTJDQkMtSFMzODQiLCJBMjU2Q0JDLUhTNTEyIiwiQTEyOEdDTSIsIkExOTJHQ00iLCJBMjU2R0NNIiwiWEMyMFAiXSwiZGlzcGxheV92YWx1ZXNfc3VwcG9ydGVkIjpbInBhZ2UiXSwiY2xhaW1fdHlwZXNfc3VwcG9ydGVkIjpbIm5vcm1hbCJdLCJjbGFpbXNfc3VwcG9ydGVkIjpbInN1YiJdLCJjbGFpbXNfcGFyYW1ldGVyX3N1cHBvcnRlZCI6dHJ1ZSwiZnJvbnRjaGFubmVsX2xvZ291dF9zdXBwb3J0ZWQiOnRydWUsImZyb250Y2hhbm5lbF9sb2dvdXRfc2Vzc2lvbl9zdXBwb3J0ZWQiOnRydWUsImJhY2tjaGFubmVsX2xvZ291dF9zdXBwb3J0ZWQiOnRydWUsImJhY2tjaGFubmVsX2xvZ291dF9zZXNzaW9uX3N1cHBvcnRlZCI6dHJ1ZX19LCJuYmYiOjE3NzM5NTA1MDMsImp3a3MiOnsia2V5cyI6W3sia3R5IjoiUlNBIiwiZSI6IkFRQUIiLCJ1c2UiOiJzaWciLCJraWQiOiIxQ2FiIiwiaWF0IjoxNzczOTMyMzA5LCJuIjoibTZ0ejdKdHVKakI1VzRrb1RNT3lodXJPaXRaZUtKeWsxWExhR0RWZWI4YW5YZHBoQVduYXFEb1REME80bU9rZTBZZzJLZDMxYlQzYTJLampGQTBZbzFVYkpkNThTSHFhcnpESDZUcWlabmdFcDdFT3ZpalNhWVVfb2p6WkxMd01UWmF2S25YN2p1aXUtU1hwTnB6WEM1a0h1MXdKUkZQdG84S2dJMkV6YW5WQTBFMlpURGxLTnRlN2NwRndlRFEzdUpMRlpmQUtJQ2M4Ung2S3hvMC02X0I4Ukp1dDlLZGdsaHlBZTdRVWg4dUMwbkJyb3pCTXBQQk1pRE5sQjhuUTV5Qnp4R0RwdzdHUU9mSXZmVmVDX1p3dVVxWkFuR2dnU29yQjBJeFM4TUc5MnZ2b2dKcksxNFBDRVBPajFEdmJGTDF1RWplYXRPSDhhM1R0eEM2RHdRIn1dfSwiaXNzIjoiaHR0cDovL2xvY2FsaG9zdDo4MDgxL3RydXN0YW5jaG9yIiwiYXV0aG9yaXR5X2hpbnRzIjpbImh0dHA6Ly9sb2NhbGhvc3Q6ODA4MS90cnVzdGFuY2hvciJdLCJleHAiOjE4MDU0ODY1MDMsImlhdCI6MTc3Mzk1MDUwMywianRpIjoiYmQ2ZmE2ZTgtNzlhNS00ODA5LTk5YjEtYTBiYTQ2ZGYyNDRhIn0.qquNOwFw8zb4-MrS4SDmD1pji92DybnEMFWo-adVQAwznQBeho3tsc17JsUlWdrYQmx8gqy0HlwmgBL4WEwQorBipx7n-QMHMfT4NBKlL0OEeQXHCnNZNZnnfPNCSjNJbKkZTbpKImlQt63pL-jHSpBiCMbGFZRhQAJExSTBFO1kledJd6Z8wQReQeevhZwcfIGspuGIUlGp7EnPr2XTBkZq5bVqADAj3YfnuuC0WtBBGMnN7hTkFU0ZM99vkHCs2kYG-vwcS4cfPYqJAMItYi2LK8dTKUCB7gJuIcjpGuBDBKHbAq0bHW95pKzgldEVZd49QyZRnENUCP4hOMCWiQ";
        } else { // RP
            return "eyJraWQiOiJ0YS1rZXktMSIsInR5cCI6ImVudGl0eS1zdGF0ZW1lbnQrand0IiwiYWxnIjoiUlMyNTYifQ.eyJzdWIiOiJodHRwOi8vbG9jYWxob3N0OjgwODEiLCJtZXRhZGF0YSI6eyJvcGVuaWRfcmVseWluZ19wYXJ0eSI6eyJyZWRpcmVjdF91cmlzIjpbImh0dHA6Ly9sb2NhbGhvc3Q6ODA4MS9jYWxsYmFjaz9jbGllbnRfbmFtZT1PaWRjQ2xpZW50Il0sImFwcGxpY2F0aW9uX3R5cGUiOiJ3ZWIiLCJyZXNwb25zZV90eXBlcyI6WyJjb2RlIl0sImdyYW50X3R5cGVzIjpbImF1dGhvcml6YXRpb25fY29kZSJdLCJzY29wZSI6Im9wZW5pZCBlbWFpbCBwcm9maWxlIiwidG9rZW5fZW5kcG9pbnRfYXV0aF9tZXRob2QiOiJwcml2YXRlX2tleV9qd3QiLCJ0b2tlbl9lbmRwb2ludF9hdXRoX3NpZ25pbmdfYWxnIjoiUlMyNTYiLCJqd2tzIjp7ImtleXMiOlt7Imt0eSI6IlJTQSIsImUiOiJBUUFCIiwidXNlIjoic2lnIiwia2lkIjoiZGVmYXVsdGp3a3MwMzI2IiwibiI6IjJtb1ZRV3c5ZkRScjg5MUU5R1dpQ29yeTB3QTBRb2tYVjlBUUZQc3FWOXJRXzVrVUx5VWNYeWZ5RHlGNWl4REd3RkdCRzhtdXh2eF9UODk5MUg0Q1ZkSnczVXlpQVdzbzVxVXlBTnFpaFhpd2lVY3hKOE1KWmpoWERidlhvNnNrMk5IcHNCT04yam90LVFRRGctMkZJT0ZBYVlXMEQzdnl1NG5rb3J0cVNGdmgwOWx4U2JzZlF6VDVuTUx5V1VVTGFmaGRjQzNLR3FSM2tVS3lOMExVQ0h0U0RtbUFiN0tHbHgzX1U4SG84MEJpT3JKNm9JdTM0V3h5WTlTNTcySXFlbl9yZHlzdW5NaDVYMWFHTHRwck43VUlCYmlORlBnNi12a0J1N3JZVzZUNFU2c0ZvajF4Mk5tZVJPcDJITTBLdmhoSThfcU8xXzZ0X1drMl8yYXE3USJ9XX0sInJlcXVlc3Rfb2JqZWN0X3NpZ25pbmdfYWxnIjoiUlMyNTYiLCJjbGllbnRfcmVnaXN0cmF0aW9uX3R5cGVzIjpbImV4cGxpY2l0IiwiYXV0b21hdGljIl0sImNsaWVudF9uYW1lIjoiQzJJRCBUZXN0IFJQIChMb2NhbGhvc3QpIiwiY29udGFjdHMiOlsiamVyb21lQGNhc2ludGhlY2xvdWQuY29tIl19fSwibmJmIjoxNzczOTUwNTAzLCJqd2tzIjp7ImtleXMiOlt7Imt0eSI6IlJTQSIsImUiOiJBUUFCIiwidXNlIjoic2lnIiwia2lkIjoibXlrZXlvaWRjZmVkZTI2IiwibiI6Im5Wb2VjWWlmRXhGb2dadW1uRDFYelA4NEtoVnVIc3I2cnZIdkdaU2xmZnQ1ZkNEVDFkZzQwRDJ3aEd1WUpHbnBfOE9VYzlsWmE3R1RpTXZqZzF0aFlYekE2Y2hrZjVtWkwtc3ZLUUpkUHRRaWVOM1FmVWhhQmlidVNOUmlpOUhrVDF0SGIyd0QzQ3NYcVVCSkV0bXU4bHdSRkluNzFhcnRDQlViQ1JsREN2TW1tbU9GVFNPN2IxUGFPSXJCaWtvV1IzbWxUR0JkcVFlcEwzNHpfU1ozbXcyMlR0X0cyemQzY2JRWndDcEl0ejNHWGplMmNoNUxXRmU2UFpuT05meUNYbUNaUUNDbm9rV3FEcTlFTGNobUNLdWxUb0tQZGdveGQ2dVV1RnotT0pCQi1NR3JrYlNHR3hNMlJmRm10UE1nS0Z5SmswbXBtbmF3TVJ4WkVxRUx6USJ9XX0sImlzcyI6Imh0dHA6Ly9sb2NhbGhvc3Q6ODA4MS90cnVzdGFuY2hvciIsImF1dGhvcml0eV9oaW50cyI6WyJodHRwOi8vbG9jYWxob3N0OjgwODEvdHJ1c3RhbmNob3IiXSwiZXhwIjoxODA1NDg2NTAzLCJpYXQiOjE3NzM5NTA1MDMsImp0aSI6ImU0NmE1ODNlLWQ2ZDEtNGQ5OC1hMDE0LWQ0ZGVmNTU2YWM2MSJ9.TW5tGDD2jIRVlVR6FYRr0jZXt1G1K6Xj2_uhsJ97WrmZko88L3ZeCp9Kw7DHcUf4R8DqtCQM1xCVHjDvd9uF-LiDGXbJ3cb-AKkCdBIzq7eOtwIZ2XREIFNOs8cQy4rlGbJFDFStLRo-eILPc7K3jvtk5Pcz8-4ZDiDXWnEFPTHrw2X5KLWJPZ0AnIYY1PP-8ChowTmcPzv2m9wHjCJfB5s24-qWqIhx_JOROd73eWpDYSETyJjM6gmkgSOG74G55KE2KKk7EixQdQPqKKSd188iRdAKan94DBmi3m158dbEO2ZWyM_9YdWtxjerAl1Zh-bgzA6H17tRGlk-oYd-7g";
        }
    }

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
