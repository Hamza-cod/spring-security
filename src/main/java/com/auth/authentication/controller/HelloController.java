package com.auth.authentication.controller;

import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;

@RestController
@RequestMapping("/api")
public class HelloController {
    @GetMapping("/hello")
    public ResponseEntity<String> sayHello (@RequestParam(defaultValue = "") String name){
        return  new ResponseEntity<>("Hello " + name, HttpStatus.OK);
    }
}
