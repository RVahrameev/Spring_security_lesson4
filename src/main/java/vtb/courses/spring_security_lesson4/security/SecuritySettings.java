package vtb.courses.spring_security_lesson4.security;

import com.nimbusds.jwt.SignedJWT;
import jakarta.servlet.*;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.annotation.Bean;
import org.springframework.core.annotation.Order;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityCustomizer;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.authentication.logout.LogoutFilter;
import org.springframework.security.web.firewall.RequestRejectedException;
import org.springframework.security.web.firewall.StrictHttpFirewall;
import org.springframework.stereotype.Component;

import java.io.IOException;
import java.text.ParseException;

import static org.springframework.security.web.context.HttpSessionSecurityContextRepository.SPRING_SECURITY_CONTEXT_KEY;

/**
 * SecuritySettings - осуществляет настройку Spring Security
 */
@Component
public class SecuritySettings {

    @Autowired
    RsaKeyVerifier rsaKeyVerifier;
    @Autowired
    RevocationCheckService tokenCheckService;

    /**
     * JWTTokenFilter - фильтр для перехвата обращения к /auth, для аутенификации через JWT токен
     */
    public class JWTTokenFilter implements Filter {
        @Override
        public void doFilter(ServletRequest servletRequest, ServletResponse servletResponse, FilterChain filterChain) throws IOException, ServletException {
            String jwtToken = ((HttpServletRequest)servletRequest).getHeader("X-Authentication");
            if (jwtToken != null) {
                // Если нам передали JWT токен, проверяем его
                try {
                    SignedJWT signedJWT = SignedJWT.parse(jwtToken);
                    // Проверяем токен по списку отозванных токенов и осуществяем его верификацию
                    if (
                            !tokenCheckService.IsRevocate(jwtToken)
                            &&
                            rsaKeyVerifier.verify(signedJWT)
                    ) {
                        // При успешной валидации токена, аутентифицируем переданного в токене пользователя
                        SecurityContextHolder.getContext().setAuthentication(new JwtAuthenticationToken(signedJWT.getJWTClaimsSet()));
                    } else {
                        // Если валидация неуспешна деаутнтифицируем текущую сессию
                        SecurityContextHolder.getContext().setAuthentication(null);
                    }
                    // Сохраняем контекст в сессии
                    ((HttpServletRequest)servletRequest).getSession().setAttribute(SPRING_SECURITY_CONTEXT_KEY, SecurityContextHolder.getContext());
                } catch (ParseException e) {
                    System.out.println("parse exception: " + e.getMessage());
                }
            } else {
                filterChain.doFilter(servletRequest, servletResponse);
            }
        }

    }

    /**
     * handleException - общий обработчик ошибок возникающих в фильтрах
     */
    private static void  handleException(HttpServletRequest request, HttpServletResponse response, RequestRejectedException requestRejectedException) throws IOException, ServletException {
        System.out.println("exception: " + requestRejectedException.getMessage());
    }

    /**
     * initSecurity - настройка Spring Security HTTP Firewall
     */
    @Bean
    public WebSecurityCustomizer initSecurity() {

        return web -> web
                .requestRejectedHandler(SecuritySettings::handleException)
                .httpFirewall(new StrictHttpFirewall())
                ;
    }

    /**
     * filterChainWhiteList - фильтр для отлова и проверки запроса доступа по токену
     */
    @Bean @Order(1)
    SecurityFilterChain filterChainCheckToken(HttpSecurity http) throws Exception{
        return http
                .securityMatcher("/auth**")
                .addFilterAfter(new JWTTokenFilter(), LogoutFilter.class)
                .build();
    }

    /**
     * filterChainAuthenticatedAccessOnly - фильтр для разрешения доступа к страницам сайта всем пользователям
     */
    @Bean @Order(2)
    SecurityFilterChain filterChainAllAccess(HttpSecurity http) throws Exception{
        return http
                .authorizeHttpRequests(c -> c.anyRequest().permitAll())
                .build();
    }

}
