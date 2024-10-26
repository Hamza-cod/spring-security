package com.auth.authentication.service;

import com.auth.authentication.entity.User;

public interface UserService {
    User loadUserByEmail(String userEmail);
}
