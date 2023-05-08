package demo.spring.security.demo.config;

import demo.spring.security.demo.services.UserService;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.authentication.dao.DaoAuthenticationProvider;
import org.springframework.security.config.annotation.method.configuration.EnableGlobalMethodSecurity;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityCustomizer;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;

@Configuration
@EnableWebSecurity
/**
 *
 * https://www.toptal.com/spring/spring-security-tutorial
 * https://www.bezkoder.com/websecurityconfigureradapter-deprecated-spring-boot/
 *
 * securedEnabled = true enables @Secured annotation.
 * jsr250Enabled = true enables @RolesAllowed annotation.
 * prePostEnabled = true enables @PreAuthorize, @PostAuthorize, @PreFilter, @PostFilter annotations.
 *
 * the Spring Security framework defines the following annotations for web security:
 *
 * @PreAuthorize supports Spring Expression Language and is used to provide expression-based access control before executing the method.
 * @PostAuthorize supports Spring Expression Language and is used to provide expression-based access control after executing the method (provides the ability to access the method result).
 * @PreFilter supports Spring Expression Language and is used to filter the collection or arrays before executing the method based on custom security rules we define.
 * @PostFilter supports Spring Expression Language and is used to filter the returned collection or arrays after executing the method based on custom security rules we define (provides the ability to access the method result).
 * @Secured does not support Spring Expression Language and is used to specify a list of roles on a method.
 * @RolesAllowed does not support Spring Expression Language and is the JSR 250’s equivalent annotation of the @Secured annotation.
 */
@EnableGlobalMethodSecurity(
        prePostEnabled = true)
public class SecurityConfig {

    @Autowired
    private UserService userService;
    @Autowired
    private JwtAuthenticationEntryPoint jwtAuthenticationEntryPoint;
    @Autowired
    private JwtRequestFilter jwtRequestFilter;

    @Autowired
    private AccessDecisionHandlerImpl accessDecisionHandler;

    /**
     * Spring Security provides a number of filters by default, and these are enough most of the time.But of course it's sometimes necessary
     * to implement new functionality by creating a new filter to use in the chain.
     * <p>
     * SecurityFilterChain: The security filters in the SecurityFilterChain are beans registered with FilterChainProxy.
     * An application can have multiple SecurityFilterChain. FilterChainProxy uses the RequestMatcher interface on
     * HttpServletRequest to determine which SecurityFilterChain needs to be called.
     * <p>
     * look at the image url : src/main/resources/static/filterChain.jpg
     *
     * @param http
     * @return SecurityFilterChain
     * @throws Exception
     */
    @Bean
    public SecurityFilterChain filterChain(HttpSecurity http) throws Exception {

        // Enable CORS and disable CSRF
        http.cors().and().csrf().disable()
                .authorizeRequests()
                //add endpoint and permission
                .antMatchers("/api/user/**").permitAll()
                .antMatchers("/user/save").permitAll()
                .antMatchers("/user/list").hasAuthority("admin")
                // Our private endpoints
                .anyRequest().authenticated()
                .and()
                // Set session management to stateless
                /**
                 * We can control exactly when our session gets created and how Spring Security will interact with it:
                 *
                 * always – A session will always be created if one doesn't already exist.
                 * ifRequired – A session will be created only if required (default).
                 * never – The framework will never create a session itself, but it will use one if it already exists.
                 * stateless – No session will be created or used by Spring Security.
                 */
                .sessionManagement().sessionCreationPolicy(SessionCreationPolicy.STATELESS).and()
                // Set unauthorized requests exception handler
                /**
                 * schema : src/main/resources/static/AccessDeniedHandling-2.png
                 * <p>
                 * AuthenticationEntryPoint is an interface in Spring Security. According to official documentation,
                 * AuthenticationEntryPoint is used to send an HTTP response that requests credentials from a client.
                 */
                .exceptionHandling().authenticationEntryPoint(jwtAuthenticationEntryPoint)
                /**
                 * AccessDecisionHandler is called when client is authenticated but not authorized to access given resource.
                 * Here, I add a screenshot of source code for this class. As you can see,
                 * there is not much happening except returning 403 HTTP code back to client.
                 */
                .accessDeniedHandler(accessDecisionHandler).and()
                // Add JWT token filter
                .addFilterBefore(jwtRequestFilter, UsernamePasswordAuthenticationFilter.class)
                .logout().logoutUrl("/api/user/logout").permitAll();

        http.authenticationProvider(authenticationProvider());


        return http.build();
    }

    /**
     * add service which can load userDetails and add bean to encoder password.
     * <p>
     * Spring's Security DaoAuthenticationProvider is a simple authentication provider that uses a Data Access Object (DAO)
     * to retrieve user information from a relational database. It leverages a UserDetailsService (as a DAO) in order
     * to lookup the username, password and GrantedAuthority.
     *
     * @return DaoAuthenticationProvider
     */

    @Bean
    public DaoAuthenticationProvider authenticationProvider() {
        DaoAuthenticationProvider authProvider = new DaoAuthenticationProvider();

        authProvider.setUserDetailsService(userService);
        authProvider.setPasswordEncoder(passwordEncoder());

        return authProvider;
    }

    @Bean
    public WebSecurityCustomizer webSecurityCustomizer() {
        return (web) -> web.debug(true)
                .ignoring()
                .antMatchers("/css/**", "/js/**", "/img/**", "/lib/**", "/favicon.ico");
    }

    /**
     * @return PasswordEncoder
     */
    @Bean
    public PasswordEncoder passwordEncoder() {
        return new BCryptPasswordEncoder();
    }


}
