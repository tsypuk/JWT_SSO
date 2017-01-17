package sso.utils;

import io.jsonwebtoken.Claims;
import io.jsonwebtoken.Jwts;
import sso.utils.CookieUtil;

import javax.servlet.http.HttpServletRequest;

import java.time.Instant;
import java.time.LocalDateTime;
import java.time.ZoneId;
import java.time.ZonedDateTime;
import java.util.Date;
import java.util.Optional;

public class JwtUtil {

    public static String getSubject(HttpServletRequest httpServletRequest, String jwtTokenCookieName, String signingKey){
        String token = CookieUtil.getValue(httpServletRequest, jwtTokenCookieName);
        if(token == null) return null;
        return Jwts.parser().setSigningKey(signingKey).parseClaimsJws(token).getBody().getSubject();
    }

    public static boolean isExpired(HttpServletRequest httpServletRequest, String jwtTokenCookieName, String signinKey) {
        String token = CookieUtil.getValue(httpServletRequest, jwtTokenCookieName);
        if (token == null) return true;
        Claims body = Jwts.parser().setSigningKey(signinKey).parseClaimsJws(token).getBody();
        Optional<Date> expirationDateOptional = Optional.ofNullable(body.getExpiration());
        if (!expirationDateOptional.isPresent()) {
            return true;
        }
        Instant instant = expirationDateOptional.get().toInstant();
        ZonedDateTime zdt = instant.atZone(ZoneId.systemDefault());
        LocalDateTime expirationLocalDateTime = zdt.toLocalDateTime();

        // The token is expired
        if (LocalDateTime.now().isAfter(expirationLocalDateTime)) {
            return true;
        }

        return false;
    }

    public static LocalDateTime getTokenExpirationDate(HttpServletRequest httpServletRequest, String jwtTokenCookieName, String signinKey) {
        String token = CookieUtil.getValue(httpServletRequest, jwtTokenCookieName);
        Date expirationDate = Jwts.parser().setSigningKey(signinKey)
                                  .parseClaimsJws(token)
                                  .getBody()
                                  .getExpiration();
        if (expirationDate == null) {
            return LocalDateTime.now();
        }
        Instant instant = expirationDate.toInstant();
        ZonedDateTime zdt = instant.atZone(ZoneId.systemDefault());
        LocalDateTime expirationLocalDateTime = zdt.toLocalDateTime();
        return expirationLocalDateTime;
    }
}