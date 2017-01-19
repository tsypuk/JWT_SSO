package sso.utils;

import org.junit.Assert;
import org.junit.Ignore;
import org.junit.Test;
import org.springframework.mock.web.MockHttpServletResponse;

import javax.servlet.http.Cookie;

public class CookieUtilTest {
    private static final String JWT_TOKEN_COOKIE_NAME = "JWT-TOKEN";
    private static final String SIGNING_KEY = "SIGNING_KEY";
    private static final String SUBJECT = "admin";
    private static final String TOKEN = "TOKEN";

    @Test
    @Ignore
    public void clear() throws Exception {
        MockHttpServletResponse httpServletResponse = new MockHttpServletResponse();
        httpServletResponse.addCookie(new Cookie(JWT_TOKEN_COOKIE_NAME, TOKEN));
        CookieUtil.clear(httpServletResponse, JWT_TOKEN_COOKIE_NAME);
        Cookie cookie = httpServletResponse.getCookie(JWT_TOKEN_COOKIE_NAME);
        Assert.assertNull(cookie.getValue());
    }

}