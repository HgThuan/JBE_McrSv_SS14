package com.identity.config;

import com.identity.model.User;
import com.identity.repository.UserRepository;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.CommandLineRunner;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Component;

import java.util.Set;

@Component
public class DataInitializer implements CommandLineRunner {

    private static final Logger logger = LoggerFactory.getLogger(DataInitializer.class);

    @Autowired
    private UserRepository userRepository;

    @Autowired
    private PasswordEncoder passwordEncoder;

    @Override
    public void run(String... args) throws Exception {
        if (!userRepository.existsByUsername("admin")) {
            User admin = new User(
                    "admin",
                    "admin@example.com",
                    passwordEncoder.encode("password123"),
                    Set.of("ROLE_ADMIN", "ROLE_USER")
            );
            userRepository.save(admin);
            logger.info(">>> Khởi tạo tài khoản mẫu ADMIN: username=admin, password=password123");
        }

        if (!userRepository.existsByUsername("user")) {
            User user = new User(
                    "user",
                    "user@example.com",
                    passwordEncoder.encode("password123"),
                    Set.of("ROLE_USER")
            );
            userRepository.save(user);
            logger.info(">>> Khởi tạo tài khoản mẫu USER: username=user, password=password123");
        }
    }
}
