package com.identity.controller;

import com.identity.dto.request.LoginRequest;
import com.identity.dto.request.RegisterRequest;
import com.identity.dto.request.TokenRefreshRequest;
import com.identity.dto.response.JwtResponse;
import com.identity.dto.response.MessageResponse;
import com.identity.dto.response.TokenRefreshResponse;
import com.identity.dto.response.TokenResponseDTO;
import com.identity.exception.TokenRefreshException;
import com.identity.model.RefreshToken;
import com.identity.model.User;
import com.identity.repository.UserRepository;
import com.identity.security.jwt.JwtUtils;
import com.identity.security.services.RefreshTokenService;
import com.identity.security.services.TokenBlacklistService;
import com.identity.security.services.UserDetailsImpl;
import jakarta.validation.Valid;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.ResponseEntity;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.web.bind.annotation.*;

import java.util.HashSet;
import java.util.List;
import java.util.Set;
import java.util.stream.Collectors;

@CrossOrigin(origins = "*", maxAge = 3600)
@RestController
@RequestMapping("/api/auth")
public class AuthController {

    @Autowired
    private AuthenticationManager authenticationManager;

    @Autowired
    private UserRepository userRepository;

    @Autowired
    private PasswordEncoder encoder;

    @Autowired
    private JwtUtils jwtUtils;

    @Autowired
    private RefreshTokenService refreshTokenService;

    /**
     * API POST /api/auth/login
     * 1. Xác thực username/password thành công.
     * 2. Gọi JwtUtils tạo Access Token.
     * 3. Gọi RefreshTokenService tạo Refresh Token.
     * 4. Trả về DTO JwtResponse chứa cả hai.
     */
    @PostMapping("/login")
    public ResponseEntity<?> authenticateUser(@Valid @RequestBody LoginRequest loginRequest) {
        // 1. Xác thực username/password thành công
        Authentication authentication = authenticationManager.authenticate(
                new UsernamePasswordAuthenticationToken(loginRequest.getUsername(), loginRequest.getPassword()));

        SecurityContextHolder.getContext().setAuthentication(authentication);

        UserDetailsImpl userDetails = (UserDetailsImpl) authentication.getPrincipal();

        // 2. Gọi JwtUtils tạo Access Token
        String jwt = jwtUtils.generateAccessToken(userDetails);

        List<String> roles = userDetails.getAuthorities().stream()
                .map(GrantedAuthority::getAuthority)
                .collect(Collectors.toList());

        // 3. Gọi RefreshTokenService tạo Refresh Token
        RefreshToken refreshToken = refreshTokenService.createRefreshToken(userDetails.getId());

        // 4. Trả về DTO (Data Transfer Object) chứa cả hai
        return ResponseEntity.ok(new JwtResponse(
                jwt,
                refreshToken.getToken(),
                userDetails.getId(),
                userDetails.getUsername(),
                userDetails.getEmail(),
                roles));
    }

    /**
     * API POST /api/auth/refreshtoken
     * Cấp mới Access Token bằng Refresh Token hợp lệ
     */
    @PostMapping("/refreshtoken")
    public ResponseEntity<?> refreshToken(@Valid @RequestBody TokenRefreshRequest request) {
        String requestRefreshToken = request.getRefreshToken();

        return refreshTokenService.findByToken(requestRefreshToken)
                .map(refreshTokenService::verifyExpiration)
                .map(RefreshToken::getUser)
                .map(user -> {
                    String token = jwtUtils.generateAccessToken(user);
                    return ResponseEntity.ok(new TokenRefreshResponse(token, requestRefreshToken));
                })
                .orElseThrow(() -> new TokenRefreshException(requestRefreshToken,
                        "Refresh token is not in database!"));
    }

    /**
     * API POST /api/auth/refresh
     * Cơ chế Token Rotation: Cấp Access Token mới và hủy Refresh Token cũ để cấp Refresh Token mới
     */
    @PostMapping("/refresh")
    public ResponseEntity<?> refresh(@Valid @RequestBody TokenRefreshRequest request) {
        TokenResponseDTO tokenResponseDTO = refreshTokenService.refreshToken(request.getRefreshToken());
        return ResponseEntity.ok(tokenResponseDTO);
    }

    /**
     * API POST /api/auth/register
     * Đăng ký người dùng mới
     */
    @PostMapping("/register")
    public ResponseEntity<?> registerUser(@Valid @RequestBody RegisterRequest signUpRequest) {
        if (userRepository.existsByUsername(signUpRequest.getUsername())) {
            return ResponseEntity
                    .badRequest()
                    .body(new MessageResponse("Error: Username is already taken!"));
        }

        if (userRepository.existsByEmail(signUpRequest.getEmail())) {
            return ResponseEntity
                    .badRequest()
                    .body(new MessageResponse("Error: Email is already in use!"));
        }

        User user = new User(signUpRequest.getUsername(),
                signUpRequest.getEmail(),
                encoder.encode(signUpRequest.getPassword()));

        Set<String> strRoles = signUpRequest.getRoles();
        Set<String> roles = new HashSet<>();

        if (strRoles == null || strRoles.isEmpty()) {
            roles.add("ROLE_USER");
        } else {
            strRoles.forEach(role -> {
                if (role.equalsIgnoreCase("admin")) {
                    roles.add("ROLE_ADMIN");
                } else {
                    roles.add("ROLE_USER");
                }
            });
        }

        user.setRoles(roles);
        userRepository.save(user);

        return ResponseEntity.ok(new MessageResponse("User registered successfully!"));
    }

    @Autowired
    private TokenBlacklistService tokenBlacklistService;

    /**
     * API POST /api/auth/logout
     * Thu hồi Access Token đưa vào Redis Blacklist với TTL và xóa Refresh Token tương ứng
     */
    @PostMapping("/logout")
    public ResponseEntity<?> logoutUser(jakarta.servlet.http.HttpServletRequest request) {
        String headerAuth = request.getHeader("Authorization");
        String jwt = null;
        if (org.springframework.util.StringUtils.hasText(headerAuth) && headerAuth.startsWith("Bearer ")) {
            jwt = headerAuth.substring(7);
        }

        if (jwt != null && jwtUtils.validateJwtToken(jwt)) {
            tokenBlacklistService.logout(jwt);
            return ResponseEntity.ok(new MessageResponse("Đăng xuất thành công! Access Token đã được đưa vào Redis Blacklist."));
        }

        return ResponseEntity.badRequest().body(new MessageResponse("Error: Yêu cầu Header Authorization Bearer Token hợp lệ để đăng xuất!"));
    }
}
