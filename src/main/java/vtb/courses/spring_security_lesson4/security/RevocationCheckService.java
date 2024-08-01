package vtb.courses.spring_security_lesson4.security;

public interface RevocationCheckService {
    boolean IsRevocate(String token);
}
