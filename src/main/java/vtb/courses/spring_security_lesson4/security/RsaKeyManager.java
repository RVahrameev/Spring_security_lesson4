package vtb.courses.spring_security_lesson4.security;

import com.nimbusds.jose.JOSEException;
import com.nimbusds.jose.JWSVerifier;
import com.nimbusds.jose.crypto.RSASSAVerifier;
import com.nimbusds.jose.jwk.RSAKey;
import com.nimbusds.jose.util.JSONObjectUtils;
import com.nimbusds.jwt.SignedJWT;
import org.springframework.stereotype.Component;

import java.io.FileNotFoundException;
import java.io.FileReader;
import java.io.IOException;
import java.text.ParseException;
import java.util.Map;
import java.util.*;

@Component
public class RsaKeyManager implements RsaKeyVerifier{
    private RSAKey[] rsaKeys;

    public RsaKeyManager() {
        try {
            // Подгружаем все имеющиеся RSA ключи из файла
            char[] buff = new char[20000];
            FileReader jsonReader = new FileReader("./src/main/resources/keyset.json");
            int jsonLen = jsonReader.read(buff, 0, 20000);
            String jsonString = String.valueOf(buff, 0, jsonLen);
            Map<String, Object> keys = JSONObjectUtils.parse(jsonString);
            List<Map<String, Object>> keyList = (List<Map<String, Object>>)keys.get("keys");
            rsaKeys = new RSAKey[keyList.size()];
            for (int i = 0; i < keyList.size(); i++) {
                rsaKeys[i] = RSAKey.parse(keyList.get(i));
            }
        } catch (FileNotFoundException e) {
        } catch (IOException e) {
        } catch (ParseException e) {
        }
    }

    /**
     *   verify - проверка JWT токена по имеющимся RSA ключам
     */
    public boolean verify(SignedJWT signedJWT) {
        boolean res = false;
        for (int i = 0; i < rsaKeys.length; i++) {
            try {
                JWSVerifier verifier = new RSASSAVerifier(rsaKeys[i]);
                if (signedJWT.verify(verifier)) {
                    return true;
                }
            } catch (JOSEException e) {
            }

        }
        return res;
    }
}
