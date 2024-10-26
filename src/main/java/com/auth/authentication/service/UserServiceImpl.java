package com.auth.authentication.service;

import com.auth.authentication.entity.User;
import com.auth.authentication.repository.UserRepository;
import lombok.AllArgsConstructor;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.stereotype.Service;

@Service
@AllArgsConstructor
public class UserServiceImpl implements UserService {
    private final UserRepository userRepository;
    @Override
    public User loadUserByEmail(String userEmail) {
        return userRepository.findByEmail(userEmail).orElseThrow(()->
                new UsernameNotFoundException("The provided email not found"));
    }
}
