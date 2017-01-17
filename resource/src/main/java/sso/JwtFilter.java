package sso;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.stereotype.Component;
import org.springframework.web.filter.OncePerRequestFilter;

import javax.servlet.FilterChain;
import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import java.io.IOException;

import sso.utils.JwtUtil;

@Component
public class JwtFilter extends OncePerRequestFilter {

    private final String JWT_TOKEN_COOKIE_NAME = "JWT-TOKEN";
    private final String SIGNING_KEY = "signingKey";

    private static final Logger LOGGER = LoggerFactory.getLogger(JwtFilter.class);

    @Override
    protected void doFilterInternal(HttpServletRequest httpServletRequest, HttpServletResponse httpServletResponse,
                                    FilterChain filterChain) throws ServletException, IOException {
        try {
            String username = JwtUtil.getSubject(httpServletRequest, JWT_TOKEN_COOKIE_NAME, SIGNING_KEY);
            boolean isExpired = JwtUtil.isExpired(httpServletRequest, JWT_TOKEN_COOKIE_NAME, SIGNING_KEY);

            if ((username == null) || (isExpired)) {
                String authService = this.getFilterConfig().getInitParameter("services.auth");
                httpServletResponse.sendRedirect(authService + "?redirect=" + httpServletRequest.getRequestURL());
            } else {
                httpServletRequest.setAttribute("username", username);
                filterChain.doFilter(httpServletRequest, httpServletResponse);
            }
        } catch (io.jsonwebtoken.ExpiredJwtException ex) {
            LOGGER.error("JWT token has expired. Redirecting to authentication service for login.");
            String authService = this.getFilterConfig().getInitParameter("services.auth");
            httpServletResponse.sendRedirect(authService + "?redirect=" + httpServletRequest.getRequestURL());
        } catch (io.jsonwebtoken.SignatureException ex) {
            LOGGER.error("The signature of JWT does not match.");
            String authService = this.getFilterConfig().getInitParameter("services.auth");
            httpServletResponse.sendRedirect(authService + "?redirect=" + httpServletRequest.getRequestURL());
        }
    }
}