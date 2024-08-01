package vtb.courses.spring_security_lesson4.security;

import com.nimbusds.jwt.SignedJWT;

public interface RsaKeyVerifier {
    public boolean verify(SignedJWT signedJWT);
}
