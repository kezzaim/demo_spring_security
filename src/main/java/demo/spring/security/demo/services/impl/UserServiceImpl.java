package demo.spring.security.demo.services.impl;

import demo.spring.security.demo.model.User;
import demo.spring.security.demo.dao.UserRepository;
import demo.spring.security.demo.services.UserService;
import org.apache.log4j.Logger;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.stereotype.Service;

import java.util.List;

@Service("userService")
public class UserServiceImpl implements UserService {

    private static final Logger log = Logger.getLogger(UserServiceImpl.class);
    @Autowired
    private UserRepository userRepository;

    @Override
    public User loadUserByUsername(String username) throws UsernameNotFoundException {
        if (username.isEmpty()) {
            log.error("user name is empty");
            return null;
        }
        return this.userRepository.findUserByUsername(username);
    }

    @Override
    public User save(User user) {
        log.info("UserServiceImpl ----save:");
        log.info("user " + user.toString());
        return this.userRepository.save(user);
    }

    @Override
    public List<User> getAllUsers() {
        return this.userRepository.findAll();
    }

    @Override
    public User update(User user) {
        return this.userRepository.save(user);
    }
}
