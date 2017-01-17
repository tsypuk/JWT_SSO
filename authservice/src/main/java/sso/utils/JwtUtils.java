package sso.utils;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import io.jsonwebtoken.Claims;
import io.jsonwebtoken.JwtBuilder;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.SignatureAlgorithm;

import javax.servlet.http.HttpServletRequest;

import java.time.Instant;
import java.time.LocalDateTime;
import java.time.ZoneId;
import java.time.ZonedDateTime;
import java.util.Date;

public class JwtUtils {

    private static final Logger LOGGER = LoggerFactory.getLogger(JwtUtils.class);
    private static final String AUTH_SERVICE_NAME = "Authorization service.";

    public static String generateToken(String signingKey, String subject) {
        long nowMillis = System.currentTimeMillis();
        Date issuedDate = new Date(nowMillis);

        Instant instant = Instant.ofEpochMilli(issuedDate.getTime());
        ZonedDateTime zdt = instant.atZone(ZoneId.systemDefault());
        LocalDateTime expirationDate = zdt.toLocalDateTime();
        expirationDate = expirationDate.plusMinutes(1);

        Claims claims = Jwts.claims();
        claims.setSubject(subject);
        claims.setIssuer(AUTH_SERVICE_NAME);
        claims.setIssuedAt(issuedDate);
        claims.setExpiration(Date.from(expirationDate.atZone(ZoneId.systemDefault()).toInstant()));
        claims.put("serviceName", "SOME_SERVICE");
        claims.put("userRoleForService", "ADMIN_ROLE");

        JwtBuilder builder = Jwts.builder()
                .setClaims(claims)
                .signWith(SignatureAlgorithm.HS256, signingKey);

        String jsonWebToken = builder.compact();

        LOGGER.info("JWT details issued at: {}, expiration at: {}, token value: {}", issuedDate, expirationDate, jsonWebToken);
        return jsonWebToken;
    }

    public static String getSubject(HttpServletRequest httpServletRequest, String jwtTokenCookieName, String
            signingKey) {
        String token = CookieUtils.getValue(httpServletRequest, jwtTokenCookieName);
        if (token == null) return null;
        return Jwts.parser().setSigningKey(signingKey).parseClaimsJws(token).getBody().getSubject();
    }
}