package sso;

import org.springframework.stereotype.Controller;
import org.springframework.web.bind.annotation.RequestMapping;

import javax.servlet.http.HttpServletResponse;

import sso.utils.CookieUtil;

@Controller
public class ResourceController {
    private static final String JWT_TOKEN_COOKIE_NAME = "JWT-TOKEN";

    @RequestMapping("/")
    public String home() {
        return "redirect:/protected-resource";
    }

    @RequestMapping("/protected-resource")
    public String protectedResource() {
        return "protected-resource";
    }

    @RequestMapping("/logout")
    public String logout(HttpServletResponse httpServletResponse) {
        CookieUtil.clear(httpServletResponse, JWT_TOKEN_COOKIE_NAME);
        return "redirect:/";
    }
}