package com.identity;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.identity.dto.request.LoginRequest;
import com.identity.dto.request.TokenRefreshRequest;
import com.identity.model.RefreshToken;
import com.identity.model.User;
import com.identity.repository.RefreshTokenRepository;
import com.identity.repository.UserRepository;
import com.identity.security.jwt.JwtUtils;
import com.identity.security.services.RefreshTokenService;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.autoconfigure.web.servlet.AutoConfigureMockMvc;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.http.MediaType;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.test.context.ActiveProfiles;
import org.springframework.test.web.servlet.MockMvc;
import org.springframework.test.web.servlet.MvcResult;

import java.time.Instant;
import java.util.Set;

import static org.assertj.core.api.Assertions.assertThat;
import static org.hamcrest.Matchers.is;
import static org.hamcrest.Matchers.notNullValue;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.jsonPath;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

@SpringBootTest
@AutoConfigureMockMvc
@ActiveProfiles("test")
class IdentityServiceApplicationTests {

    @Autowired
    private MockMvc mockMvc;

    @Autowired
    private ObjectMapper objectMapper;

    @Autowired
    private UserRepository userRepository;

    @Autowired
    private RefreshTokenRepository refreshTokenRepository;

    @Autowired
    private RefreshTokenService refreshTokenService;

    @Autowired
    private JwtUtils jwtUtils;

    @Autowired
    private PasswordEncoder passwordEncoder;

    @BeforeEach
    void setUp() {
        refreshTokenRepository.deleteAll();
        userRepository.deleteAll();

        User testUser = new User("testuser", "test@example.com", passwordEncoder.encode("password123"), Set.of("ROLE_USER"));
        userRepository.save(testUser);
    }

    @Test
    @DisplayName("Kiểm tra JwtUtils tạo Access Token và giải mã claims chính xác")
    void testJwtUtils() {
        User user = userRepository.findByUsername("testuser").orElseThrow();
        String token = jwtUtils.generateAccessToken(user);

        assertThat(token).isNotNull().isNotBlank();
        assertThat(jwtUtils.validateJwtToken(token)).isTrue();
        assertThat(jwtUtils.getUserNameFromJwtToken(token)).isEqualTo("testuser");
    }

    @Test
    @DisplayName("Kiểm tra RefreshTokenService tạo Refresh Token và lưu vào DB")
    void testRefreshTokenService() {
        User user = userRepository.findByUsername("testuser").orElseThrow();
        RefreshToken refreshToken = refreshTokenService.createRefreshToken(user.getId());

        assertThat(refreshToken).isNotNull();
        assertThat(refreshToken.getToken()).isNotBlank();
        assertThat(refreshToken.getExpiryDate()).isAfter(Instant.now());
        assertThat(refreshToken.getUser().getUsername()).isEqualTo("testuser");

        // Kiểm tra verifyExpiration với token còn hạn
        RefreshToken verifiedToken = refreshTokenService.verifyExpiration(refreshToken);
        assertThat(verifiedToken).isNotNull();
    }

    @Test
    @DisplayName("Kiểm tra API POST /api/auth/login trả về cả Access Token và Refresh Token")
    void testLoginSuccess() throws Exception {
        LoginRequest loginRequest = new LoginRequest("testuser", "password123");

        mockMvc.perform(post("/api/auth/login")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(objectMapper.writeValueAsString(loginRequest)))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.accessToken", notNullValue()))
                .andExpect(jsonPath("$.refreshToken", notNullValue()))
                .andExpect(jsonPath("$.tokenType", is("Bearer")))
                .andExpect(jsonPath("$.username", is("testuser")))
                .andExpect(jsonPath("$.roles[0]", is("ROLE_USER")));
    }

    @Test
    @DisplayName("Kiểm tra luồng Refresh Token cấp mới Access Token")
    void testRefreshTokenFlow() throws Exception {
        // 1. Đăng nhập để lấy tokens
        LoginRequest loginRequest = new LoginRequest("testuser", "password123");
        MvcResult loginResult = mockMvc.perform(post("/api/auth/login")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(objectMapper.writeValueAsString(loginRequest)))
                .andExpect(status().isOk())
                .andReturn();

        String responseContent = loginResult.getResponse().getContentAsString();
        String refreshToken = objectMapper.readTree(responseContent).get("refreshToken").asText();

        // 2. Gửi request làm mới token
        TokenRefreshRequest refreshRequest = new TokenRefreshRequest(refreshToken);
        mockMvc.perform(post("/api/auth/refreshtoken")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(objectMapper.writeValueAsString(refreshRequest)))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.accessToken", notNullValue()))
                .andExpect(jsonPath("$.refreshToken", is(refreshToken)))
                .andExpect(jsonPath("$.tokenType", is("Bearer")));
    }

    @Test
    @DisplayName("Kiểm tra truy cập Protected API bằng Access Token")
    void testProtectedEndpointWithAccessToken() throws Exception {
        User user = userRepository.findByUsername("testuser").orElseThrow();
        String accessToken = jwtUtils.generateAccessToken(user);

        // Gọi API với Bearer token hợp lệ
        mockMvc.perform(get("/api/test/user")
                        .header("Authorization", "Bearer " + accessToken))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.message", notNullValue()));

        // Gọi API không có Authorization header -> 401 Unauthorized
        mockMvc.perform(get("/api/test/user"))
                .andExpect(status().isUnauthorized());
    }

    @Test
    @DisplayName("Kiểm tra Token Rotation (3 bước): B1 Login lấy A và R1, B2 Refresh R1 lấy B và R2, B3 Replay R1 nhận 403 Forbidden")
    void testTokenRotationScenario() throws Exception {
        // Bước 1: Login để lấy cặp Token A (Access) và R1 (Refresh)
        LoginRequest loginRequest = new LoginRequest("testuser", "password123");
        MvcResult loginResult = mockMvc.perform(post("/api/auth/login")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(objectMapper.writeValueAsString(loginRequest)))
                .andExpect(status().isOk())
                .andReturn();

        String loginResponse = loginResult.getResponse().getContentAsString();
        String tokenA = objectMapper.readTree(loginResponse).get("accessToken").asText();
        String tokenR1 = objectMapper.readTree(loginResponse).get("refreshToken").asText();

        assertThat(tokenA).isNotBlank();
        assertThat(tokenR1).isNotBlank();

        // Bước 2: Gửi R1 vào API /refresh. Xác nhận nhận được cặp Token mới là B (Access) và R2 (Refresh)
        TokenRefreshRequest refreshRequest1 = new TokenRefreshRequest(tokenR1);
        MvcResult refreshResult = mockMvc.perform(post("/api/auth/refresh")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(objectMapper.writeValueAsString(refreshRequest1)))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.accessToken", notNullValue()))
                .andExpect(jsonPath("$.refreshToken", notNullValue()))
                .andExpect(jsonPath("$.tokenType", is("Bearer")))
                .andReturn();

        String refreshResponse = refreshResult.getResponse().getContentAsString();
        String tokenB = objectMapper.readTree(refreshResponse).get("accessToken").asText();
        String tokenR2 = objectMapper.readTree(refreshResponse).get("refreshToken").asText();

        // R2 phải hoàn toàn mới và khác R1
        assertThat(tokenR2).isNotEqualTo(tokenR1);

        // Bước 3: Gửi lại R1 vào API /refresh lần nữa.
        // Kết quả mong đợi: Hệ thống trả về lỗi 403 Forbidden (vì R1 đã bị xóa khỏi DB ở Bước 2).
        mockMvc.perform(post("/api/auth/refresh")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(objectMapper.writeValueAsString(refreshRequest1)))
                .andExpect(status().isForbidden())
                .andExpect(jsonPath("$.statusCode", is(403)))
                .andExpect(jsonPath("$.message", notNullValue()));

        // Bước 4: Kiểm tra R2 vẫn dùng được để tiếp tục chu kỳ Rotation lấy R3
        TokenRefreshRequest refreshRequest2 = new TokenRefreshRequest(tokenR2);
        mockMvc.perform(post("/api/auth/refresh")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(objectMapper.writeValueAsString(refreshRequest2)))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.refreshToken", notNullValue()))
                .andExpect(jsonPath("$.refreshToken").value(org.hamcrest.Matchers.not(tokenR2)));
    }

    @Autowired
    private com.identity.security.services.TokenBlacklistService tokenBlacklistService;

    @Test
    @DisplayName("Kiểm tra Access Token được phát hành có chứa claim jti duy nhất")
    void testAccessTokenContainsJtiClaim() {
        User user = userRepository.findByUsername("testuser").orElseThrow();
        String token = jwtUtils.generateAccessToken(user);

        String jti = jwtUtils.getJtiFromJwtToken(token);
        assertThat(jti).isNotNull().isNotBlank();
        assertThat(java.util.UUID.fromString(jti)).isNotNull();
    }

    @Test
    @DisplayName("Kiểm tra Logout lưu token vào Redis Blacklist và chặn truy cập tức thì")
    void testLogoutBlacklistsTokenInRedis() throws Exception {
        // 1. Đăng nhập lấy Access Token
        LoginRequest loginRequest = new LoginRequest("testuser", "password123");
        MvcResult loginResult = mockMvc.perform(post("/api/auth/login")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(objectMapper.writeValueAsString(loginRequest)))
                .andExpect(status().isOk())
                .andReturn();

        String token = objectMapper.readTree(loginResult.getResponse().getContentAsString()).get("accessToken").asText();

        // 2. Trước khi logout: Gọi Protected API thành công
        mockMvc.perform(get("/api/test/user")
                        .header("Authorization", "Bearer " + token))
                .andExpect(status().isOk());

        // 3. Gọi Logout với Bearer Token
        mockMvc.perform(post("/api/auth/logout")
                        .header("Authorization", "Bearer " + token))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.message", notNullValue()));

        // 4. Kiểm tra Redis: Token đã nằm trong Blacklist
        assertThat(tokenBlacklistService.isTokenBlacklisted(token)).isTrue();

        // 5. Sau khi logout: Gọi lại Protected API với token đó bị chặn 401 Unauthorized
        mockMvc.perform(get("/api/test/user")
                        .header("Authorization", "Bearer " + token))
                .andExpect(status().isUnauthorized());
    }
}
