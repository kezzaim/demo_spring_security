package demo.spring.security.demo.controller;

import demo.spring.security.demo.model.User;
import demo.spring.security.demo.services.UserService;
import org.apache.log4j.Logger;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.validation.annotation.Validated;
import org.springframework.web.bind.annotation.*;

import java.util.List;

@RestController
@RequestMapping("/user")
public class AppController {

    private static final Logger log = Logger.getLogger(AppController.class);

    @Autowired
    private UserService userService;
    @Autowired
    private PasswordEncoder passwordEncoder;

    @PostMapping("/save")
    public User saveClient(@RequestBody @Validated User user) {
        log.info("UserController --- save");
        log.info("user " + user.toString());
        user.setPassword(this.passwordEncoder.encode(user.getPassword()));
        log.info("user with password encoder :  " + user.toString());
        return this.userService.save(user);
    }

    @GetMapping("/list")
    public List<User> getAllUsers() {
        System.out.println("appController ---get all user");
        return this.userService.getAllUsers();
    }

    @PostMapping("/current/update")
    public User updateCurrentUser(@RequestParam String username) {
        log.info("AppController ---updateCurrentUser: " + username);
        Authentication aut = SecurityContextHolder.getContext().getAuthentication();
        User user = (User) aut.getPrincipal();
        log.debug("current user :  " + user.toString());
        user.setUsername(username);

        log.debug("user principal : " + user);
        ((User) aut.getPrincipal()).setUsername(username);
        return this.userService.update(user);
    }

    @GetMapping("/test")
    public String getMsg() {
        return "this api for your test authority!";
    }
}
