package demo.spring.security.demo.services;

import demo.spring.security.demo.model.User;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.UsernameNotFoundException;

import java.util.List;


public interface UserService extends UserDetailsService{
    @Override
    User loadUserByUsername(String username) throws UsernameNotFoundException;
    User save(User user);

    List<User> getAllUsers();

    User update(User user);


}
