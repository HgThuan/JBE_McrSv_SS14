package com.identity.controller;

import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.web.bind.annotation.CrossOrigin;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import java.util.HashMap;
import java.util.Map;

@CrossOrigin(origins = "*", maxAge = 3600)
@RestController
@RequestMapping("/api/test")
public class TestController {

    @GetMapping("/all")
    public Map<String, String> allAccess() {
        Map<String, String> response = new HashMap<>();
        response.put("message", "Public Content - Không yêu cầu đăng nhập.");
        return response;
    }

    @GetMapping("/user")
    @PreAuthorize("hasRole('USER') or hasRole('ADMIN')")
    public Map<String, String> userAccess() {
        Map<String, String> response = new HashMap<>();
        response.put("message", "User/Admin Content - Đã xác thực thành công qua Access Token!");
        return response;
    }

    @GetMapping("/admin")
    @PreAuthorize("hasRole('ADMIN')")
    public Map<String, String> adminAccess() {
        Map<String, String> response = new HashMap<>();
        response.put("message", "Admin Content - Chỉ dành riêng cho quyền ADMIN.");
        return response;
    }
}
