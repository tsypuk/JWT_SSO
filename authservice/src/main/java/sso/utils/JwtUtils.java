package sso.utils;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import io.jsonwebtoken.Claims;
import io.jsonwebtoken.JwtBuilder;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.SignatureAlgorithm;

import java.time.Duration;
import java.time.Instant;
import java.util.Date;

public class JwtUtils {

    private static final Logger LOGGER = LoggerFactory.getLogger(JwtUtils.class);
    private static final String AUTH_SERVICE_NAME = "Authorization service.";

    public static String generateToken(String signingKey, String subject, int expirationMinutes) {
        Date issuedDate = new Date();
        Instant expiredInstant = Instant.ofEpochMilli(issuedDate.getTime())
                .plus(Duration.ofMinutes(expirationMinutes));

        Claims claims = Jwts.claims();
        claims.setSubject(subject);
        claims.setIssuer(AUTH_SERVICE_NAME);
        claims.setIssuedAt(issuedDate);
        claims.setExpiration(Date.from(expiredInstant));
        claims.put("serviceName", "SOME_SERVICE");
        claims.put("userRoleForService", "ADMIN_ROLE");

        JwtBuilder builder = Jwts.builder()
                .setClaims(claims)
                .signWith(SignatureAlgorithm.HS256, signingKey);

        String jsonWebToken = builder.compact();

        LOGGER.info("JWT details issued at: {}, expiration at: {}, token value: {}", issuedDate, Date.from(expiredInstant),
                jsonWebToken);
        return jsonWebToken;
    }

}