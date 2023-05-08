package demo.spring.security.demo.config;

import demo.spring.security.demo.model.User;
import io.jsonwebtoken.Claims;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.SignatureAlgorithm;
import org.springframework.stereotype.Component;

import java.util.Date;
import java.util.HashMap;
import java.util.Map;
import java.util.function.Function;

@Component
public class JwtTokenUtil {

    private static final String SECRET_KEY = "secret_key";

    /**generate new token
     * this function tak a param user implement of userDetails to create anew token using JWT
     * @param user
     * @return
     */
    public String generateToken(User user) {
        Map<String, Object> claims = new HashMap<>();
        return createToken(claims, user.getUsername());
    }

    /**
     * @param claims is empty map
     * @param subject is String , username of current user want to connect
     * @return
     */
    private String createToken(Map<String, Object> claims, String subject) {
        long now = System.currentTimeMillis();
        long validityInMilliseconds = 3600000; // 1 hour
        //time expiration , here is one hour
        Date validity = new Date(now + validityInMilliseconds);

        return Jwts.builder()
                .setClaims(claims)
                /**
                 * The "sub" (subject) claim identifies the principal that is the subject of the JWT.
                 * The subject value MUST either be scoped to be locally unique in the context of the issuer or be globally unique.
                 * The "sub" value is a case-sensitive string containing a StringOrURI value.
                 */
                .setSubject(subject)
                //claim identifies the time at which the JWT was issued
                .setIssuedAt(new Date(now))
                //time expiration , here is one hour
                .setExpiration(validity)
                .signWith(SignatureAlgorithm.HS256, SECRET_KEY)
                //is method that generate a string (token) which user the values that inserted of Jwts.builder()
                .compact();
    }

    public Boolean validateToken(String token, User user) throws Exception {
        final String username = extractUsername(token);
        return (username.equals(user.getUsername()) && !isTokenExpired(token));
    }

    public String extractUsername(String token) throws Exception {
        return extractClaim(token, Claims::getSubject);
    }

    public Date extractExpiration(String token) throws Exception {
        return extractClaim(token, Claims::getExpiration);
    }

    public <T> T extractClaim(String token, Function<Claims, T> claimsResolver) throws Exception {
        final Claims claims = extractAllClaims(token);
        return claimsResolver.apply(claims);
    }

    private Claims extractAllClaims(String token) throws Exception {
        return Jwts.parser().setSigningKey(SECRET_KEY).parseClaimsJws(token).getBody();
    }

    private Boolean isTokenExpired(String token) throws Exception {
        return extractExpiration(token).before(new Date());
    }
}
