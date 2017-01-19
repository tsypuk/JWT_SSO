package sso.utils;

import javax.servlet.http.Cookie;
import javax.servlet.http.HttpServletRequest;
import java.time.Instant;
import java.util.Date;
import java.util.Optional;

import io.jsonwebtoken.Claims;
import io.jsonwebtoken.Jws;
import io.jsonwebtoken.Jwts;
import org.springframework.web.util.WebUtils;

public class JwtUtil {

    public static Optional<String> getSubject(HttpServletRequest httpServletRequest,
                                              String jwtTokenCookieName,
                                              String signingKey) {

        return Optional.ofNullable(WebUtils.getCookie(httpServletRequest, jwtTokenCookieName))
                       .map(Cookie::getValue)
                       .map(Jwts.parser()
                                .setSigningKey(signingKey)::parseClaimsJws)
                       .map(Jws::getBody)
                       .map(Claims::getSubject);
    }

    public static boolean isExpired(HttpServletRequest httpServletRequest,
                                    String jwtTokenCookieName,
                                    String signinKey) {

        return !Optional.ofNullable(WebUtils.getCookie(httpServletRequest, jwtTokenCookieName))
                        .map(Cookie::getValue)
                        .map(Jwts.parser().setSigningKey(signinKey)::parseClaimsJws)
                        .map(Jws::getBody)
                        .map(Claims::getExpiration)
                        .map(Date::toInstant)
                        .filter(Instant.now()::isBefore)
                        .isPresent();
    }
}
