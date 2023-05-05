package demo.spring.security.demo;

import demo.spring.security.demo.model.Role;
import demo.spring.security.demo.dao.RoleRepository;
import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.context.ConfigurableApplicationContext;

import java.util.Arrays;

@SpringBootApplication
public class DemoSpringSecurityApplication {

    public static void main(String[] args) {
        ConfigurableApplicationContext ctx = SpringApplication.run(DemoSpringSecurityApplication.class, args);

        // to initializer roles in database
//        RoleRepository rr = ctx.getBean(RoleRepository.class);
//
//        Role roleAdmin = new Role("admin");
//        Role roleUser = new Role("user");
//        Role rls[] = new Role[]{roleAdmin, roleUser};
//        rr.saveAll(Arrays.asList(rls));

    }

}
