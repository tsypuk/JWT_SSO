package sso;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Controller;
import org.springframework.ui.Model;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestMethod;

import javax.servlet.http.HttpServletResponse;

import java.util.HashMap;
import java.util.Map;

import sso.utils.CookieUtils;
import sso.utils.JwtUtils;

@Controller
public class LoginController {

    private static final Map<String, String> credentials = new HashMap<>();
    private static final Logger LOGGER = LoggerFactory.getLogger(LoginController.class);

    private final String jwtTokenCookieName;
    private final String signInKey;

    @Autowired
    public LoginController(@Value("${services.cookieName}") String jwtTokenCookieName,
                           @Value("${services.signinKey}") String signInKey) {
        this.jwtTokenCookieName = jwtTokenCookieName;
        this.signInKey = signInKey;
        loadCredentialsFromStorage();
    }

    /**
     * This can SQL, NoSQL, FileSystem...
     */
    private void loadCredentialsFromStorage() {
        credentials.put("admin", "admin");
        credentials.put("user", "password");
    }

    @RequestMapping("/")
    public String home() {
        return "redirect:/login";
    }

    @RequestMapping("/login")
    public String login() {
        return "login";
    }

    @RequestMapping(value = "login", method = RequestMethod.POST)
    public String login(HttpServletResponse httpServletResponse, String username, String password, String redirect,
                        Model model) {
        if (username == null || !credentials.containsKey(username) || !credentials.get(username).equals(password)) {
            model.addAttribute("error", "Invalid username or password!");
            LOGGER.error("Failed login attempt. Bad credentials for {}.", username);
            return "login";
        }

        String token = JwtUtils.generateToken(signInKey, username);
        CookieUtils.create(httpServletResponse, jwtTokenCookieName, token, false, -1, "localhost");

        return "redirect:" + redirect;
    }
}