package sso.utils;

import org.junit.Assert;
import org.junit.Test;
import org.springframework.mock.web.MockHttpServletRequest;

import java.time.Instant;
import java.time.LocalDateTime;
import java.time.ZoneId;
import java.time.ZonedDateTime;
import java.util.Date;
import java.util.Optional;

import javax.servlet.http.Cookie;

import io.jsonwebtoken.Claims;
import io.jsonwebtoken.JwtBuilder;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.SignatureAlgorithm;
import io.jsonwebtoken.impl.TextCodec;

public class JwtUtilTest {
    private static final String JWT_TOKEN_COOKIE_NAME = "JWT-TOKEN";
    private static final String SIGNING_KEY = "SIGNING_KEY";
    private static final String SUBJECT = "admin";

    @Test
    public void testGetSubject() {
        String token = generateToken(SIGNING_KEY, SUBJECT, 1, new Date());
        MockHttpServletRequest httpServletRequest = new MockHttpServletRequest("GET", "/localhost");
        httpServletRequest.setCookies(new Cookie(JWT_TOKEN_COOKIE_NAME, token));
        Optional<String> subject = JwtUtil.getSubject(httpServletRequest, JWT_TOKEN_COOKIE_NAME, SIGNING_KEY);
        Assert.assertTrue(subject.isPresent());
        Assert.assertEquals(SUBJECT, subject.get());
    }

    /**
     * Signature .dYWQXY8fx9fWnKdQDwuyuBRkyFp2X3tIgVefxgq9PVk
     * The changing the last character in signature does not throw
     * io.jsonwebtoken.SignatureException: JWT signature does not match locally computed signature. JWT validity cannot be asserted and should not be trusted.
     * only if we modify it by 1..3 value.
     * Looks like this digit does not pretend to work in algorithm of verification or there is a bug in length of token.
     */
    @Test(expected = io.jsonwebtoken.SignatureException.class)
    public void testJWTModifiedSignature() {
        String token = generateToken(SIGNING_KEY, SUBJECT, 3, new Date());
        token = modifyCharAtToken(token, token.length() - 1);
        MockHttpServletRequest httpServletRequest = new MockHttpServletRequest("GET", "/localhost");
        httpServletRequest.setCookies(new Cookie(JWT_TOKEN_COOKIE_NAME, token));
        JwtUtil.getSubject(httpServletRequest, JWT_TOKEN_COOKIE_NAME, SIGNING_KEY);
    }

    @Test(expected = io.jsonwebtoken.SignatureException.class)
    public void testInvalidSigningKey() {
        String token = generateToken(SIGNING_KEY, SUBJECT, 3, new Date());
        MockHttpServletRequest httpServletRequest = new MockHttpServletRequest("GET", "/localhost");
        httpServletRequest.setCookies(new Cookie(JWT_TOKEN_COOKIE_NAME, token));
        JwtUtil.getSubject(httpServletRequest, JWT_TOKEN_COOKIE_NAME, "INVALID_SIGNATURE");
    }

    private String modifyCharAtToken(String token, int position) {
        StringBuilder str = new StringBuilder(token);
        char c = str.charAt(position);
        c += 4;
        str.setCharAt(position, c);
        token = str.toString();
        return token;
    }

    /**
     * JWT is using BASE64 transformation. Was found that changing the last char + 0...3 would led to the same byte[].
     * As a result this would be also valid signature.
     */
    @Test
    public void testWeakBase64Algorithm() {
        final String signature1 = "4rvgyCnaKC2aD2gmYS_FUx_OcxqBpa5Ewe-jxXVpYjg";
        final String signature2 = "4rvgyCnaKC2aD2gmYS_FUx_OcxqBpa5Ewe-jxXVpYji";
        byte[] decode1 = TextCodec.BASE64URL.decode(signature1);
        byte[] decode2 = TextCodec.BASE64URL.decode(signature2);
        Assert.assertArrayEquals(decode1, decode2);
    }

    @Test(expected = io.jsonwebtoken.ExpiredJwtException.class)
    public void isExpired() throws Exception {
        Date expiredDate = Date.from(LocalDateTime.of(2000, 01, 01, 01, 10, 10).atZone(ZoneId.systemDefault()).toInstant());
        String token = generateToken(SIGNING_KEY, SUBJECT, 1, expiredDate);
        MockHttpServletRequest httpServletRequest = new MockHttpServletRequest("GET", "/localhost");
        httpServletRequest.setCookies(new Cookie(JWT_TOKEN_COOKIE_NAME, token));
        JwtUtil.isExpired(httpServletRequest, JWT_TOKEN_COOKIE_NAME, SIGNING_KEY);
    }

    private String generateToken(String signingKey, String subject, int expirationMinutes, Date issuedDate) {
        Instant instant = Instant.ofEpochMilli(issuedDate.getTime());
        ZonedDateTime zdt = instant.atZone(ZoneId.systemDefault());
        LocalDateTime expirationDate = zdt.toLocalDateTime();
        expirationDate = expirationDate.plusMinutes(expirationMinutes);

        Claims claims = Jwts.claims();
        claims.setSubject(subject);
        claims.setIssuer("service");
        claims.setIssuedAt(issuedDate);
        claims.setExpiration(Date.from(expirationDate.atZone(ZoneId.systemDefault()).toInstant()));
        claims.put("serviceName", "SOME_SERVICE");
        claims.put("userRoleForService", "ADMIN_ROLE");

        JwtBuilder builder = Jwts.builder()
                .setClaims(claims)
                .signWith(SignatureAlgorithm.HS256, signingKey);

        String jsonWebToken = builder.compact();

        return jsonWebToken;
    }
}