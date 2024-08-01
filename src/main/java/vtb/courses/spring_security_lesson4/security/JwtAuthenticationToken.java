package vtb.courses.spring_security_lesson4.security;

import com.nimbusds.jwt.JWTClaimsSet;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.GrantedAuthority;

import java.util.Collection;

/**
 * JwtAuthenticationToken - класс для хранения аутенификации проведённой через JWT токен
 */
public class JwtAuthenticationToken implements Authentication {
    private JWTClaimsSet claimsSet;
    private boolean isAuthenticated;
    @Override
    public Collection<? extends GrantedAuthority> getAuthorities() {
        return null;
    }

    @Override
    public Object getCredentials() {
        return claimsSet.getClaims().get("scp");
    }

    @Override
    public Object getDetails() {
        return null;
    }

    @Override
    public Object getPrincipal() {
        return null;
    }

    @Override
    public boolean isAuthenticated() {
        return isAuthenticated;
    }

    @Override
    public void setAuthenticated(boolean isAuthenticated) throws IllegalArgumentException {
        this.isAuthenticated = isAuthenticated;
    }

    @Override
    public String getName() {
        return claimsSet.getSubject();
    }

    public JWTClaimsSet getClaimsSet() {
        return new JWTClaimsSet.Builder(claimsSet).build();
    }

    public JwtAuthenticationToken(JWTClaimsSet claimsSet) {
        this.claimsSet = claimsSet;
        this.isAuthenticated = true;
    }

    @Override
    public String toString() {
        return "Authenticated = "+isAuthenticated + "    JwtAuthenticationToken{"+claimsSet+"}";
    }
}
