package demo.spring.security.demo.controller;

import demo.spring.security.demo.model.User;
import demo.spring.security.demo.config.JwtTokenUtil;
import demo.spring.security.demo.model.UserDTO;
import demo.spring.security.demo.services.UserService;
import org.apache.log4j.Logger;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.web.authentication.logout.SecurityContextLogoutHandler;
import org.springframework.web.bind.annotation.*;

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

@RestController
@RequestMapping("/api/user")
public class UserLoginController {

    private static final Logger log = Logger.getLogger(UserLoginController.class);
    @Autowired
    private UserService userService;

    @Autowired
    private JwtTokenUtil jwtTokenUtil;

    @PostMapping("/login")
    public User loginUser(@RequestBody UserDTO userDTO) {
        log.info("LogInControllerImpl ---login user ");
        User user = new User(userDTO.getUsername(),userDTO.getPassword());
        log.info("users : " + user.getUsername());
        if (user.getUsername().isEmpty())
            return null;
        user = this.userService.loadUserByUsername(user.getUsername());
        log.info("after --- users : " + user.toString());
        user.setToken(jwtTokenUtil.generateToken(user));
        return user;
    }

    @GetMapping(value = "/logout")
    public void logoutPage(HttpServletRequest request, HttpServletResponse response) {
        log.info("---- lougo out ");
        Authentication auth = SecurityContextHolder.getContext().getAuthentication();
        if (auth != null) {
            log.info("log out auth :: " + auth.getName());
            new SecurityContextLogoutHandler().logout(request, response, auth);
        }

    }
}
