package demo.spring.security.demo.config;

import demo.spring.security.demo.model.User;
import demo.spring.security.demo.services.UserService;
import io.jsonwebtoken.ExpiredJwtException;
import io.jsonwebtoken.SignatureException;
import org.apache.log4j.Logger;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.web.authentication.WebAuthenticationDetailsSource;
import org.springframework.stereotype.Component;
import org.springframework.web.filter.OncePerRequestFilter;

import javax.servlet.FilterChain;
import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;

@Component
public class JwtRequestFilter extends OncePerRequestFilter {

    private final Logger log = Logger.getLogger("JwtRequestFilter");
    @Autowired
    private UserService userService;

    @Autowired
    private JwtTokenUtil jwtTokenUtil;

    @Override
    protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response, FilterChain filterChain) throws ServletException, IOException {
        final String requestTokenHeader = request.getHeader("Authorization");

        log.debug("doFilterInternal ------ token : " + requestTokenHeader);

        String username = null;
        String jwtToken = null;
        // only the Token
        if (requestTokenHeader != null) {
            jwtToken = requestTokenHeader;
            try {
                username = jwtTokenUtil.extractUsername(jwtToken);
            } catch (IllegalArgumentException e) {
                log.error("Unable to get JWT Token");
            } catch (ExpiredJwtException e) {
                log.error("JWT Token has expired");
            } catch (SignatureException e) {
                log.error("error : " + e.getMessage());
                log.error(e, e);
            } catch (Exception e) {
                log.error(e, e);
            }
        } else {
            logger.warn("JWT Token is a null");
        }

        // Once we get the token validate it.
        if (username != null && SecurityContextHolder.getContext().getAuthentication() == null) {

            User user = this.userService.loadUserByUsername(username);

            // if token is valid configure Spring Security to manually set
            // authentication
            try {
                if (jwtTokenUtil.validateToken(jwtToken, user)) {

                    /**
                     * src/main/resources/static/spring_security_username_password_authentication_token.png
                     * https://medium.com/geekculture/spring-security-authentication-process-authentication-flow-behind-the-scenes-d56da63f04fa#:~:text=For%20example%2C%20UsernamePasswordAuthenticationToken%20is%20an,Other%20examples%20include%20OpenIDAuthenticationToken%20%2C%20RememberMeAuthenticationToken%20.
                     *
                     * UsernamePasswordAuthenticationToken is an implementation of Authentication interface.
                     * This class specifies that the authentication mechanism must be via username-password.
                     */
                    UsernamePasswordAuthenticationToken usernamePasswordAuthenticationToken = new UsernamePasswordAuthenticationToken(user, null, user.getAuthorities());
                    usernamePasswordAuthenticationToken.setDetails(new WebAuthenticationDetailsSource().buildDetails(request));
                    // After setting the Authentication in the context, we specify
                    // that the current user is authenticated. So it passes the
                    // Spring Security Configurations successfully.
                    SecurityContextHolder.getContext().setAuthentication(usernamePasswordAuthenticationToken);
                }
            } catch (Exception e) {
                log.error(e, e);
            }
        }
        filterChain.doFilter(request, response);
    }

}
