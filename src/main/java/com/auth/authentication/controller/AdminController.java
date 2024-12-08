package com.auth.authentication.controller;

import lombok.AllArgsConstructor;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.web.bind.annotation.*;

@RestController
@AllArgsConstructor
@RequestMapping("/api/v1/admin")
@PreAuthorize("hasRole('ADMIN')")
public class AdminController {
    @GetMapping
   // @PreAuthorize("hasRole('ADMIN')")
    public String get() {
        return "GET:: admin controller";
    }
    @PostMapping
//    @PreAuthorize("hasAuthority('admin:create')")
//    @Hidden
    public String post() {
        return "POST:: admin controller";
    }
    @PutMapping
//    @PreAuthorize("hasAuthority('admin:update')")
//    @Hidden
    public String put() {
        return "PUT:: admin controller";
    }
    @DeleteMapping
//    @PreAuthorize("hasAuthority('admin:delete')")
//    @Hidden
    public String delete() {
        return "DELETE:: admin controller";
    }
}
