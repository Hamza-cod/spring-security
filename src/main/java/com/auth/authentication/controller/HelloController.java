package com.auth.authentication.controller;

import com.auth.authentication.service.UserService;
import lombok.AllArgsConstructor;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;

import java.nio.file.attribute.UserPrincipalNotFoundException;
import java.security.Principal;

@RestController
@RequestMapping("/api")
@AllArgsConstructor
public class HelloController {
    private  final UserService userService;
    @GetMapping("/hello")
    public ResponseEntity<String> sayHello (@RequestParam(defaultValue = "") String name)  {
        //throw  new UserPrincipalNotFoundException("server error test");
        return  new ResponseEntity<>("Hello " + name, HttpStatus.OK);
    }
    @GetMapping("/me")
    public ResponseEntity<?> me (Principal principal)  {
        var data =  userService.loadUserByEmail(principal.getName());
        return  new ResponseEntity<>(data, HttpStatus.OK);
    }
}
