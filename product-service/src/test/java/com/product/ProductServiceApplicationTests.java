package com.product;

import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.SignatureAlgorithm;
import io.jsonwebtoken.security.Keys;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.boot.test.autoconfigure.web.servlet.AutoConfigureMockMvc;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.test.web.servlet.MockMvc;

import java.nio.charset.StandardCharsets;
import java.security.Key;
import java.util.Date;
import java.util.List;
import java.util.Map;

import static org.hamcrest.Matchers.is;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.delete;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.jsonPath;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

@SpringBootTest
@AutoConfigureMockMvc
class ProductServiceApplicationTests {

    @Autowired
    private MockMvc mockMvc;

    @Value("${app.jwt.secret}")
    private String jwtSecret;

    private String generateTestToken(String username, List<String> roles) {
        Key key = Keys.hmacShaKeyFor(jwtSecret.getBytes(StandardCharsets.UTF_8));
        return Jwts.builder()
                .setClaims(Map.of("roles", roles))
                .setSubject(username)
                .setIssuedAt(new Date())
                .setExpiration(new Date(System.currentTimeMillis() + 900000))
                .signWith(key, SignatureAlgorithm.HS256)
                .compact();
    }

    @Test
    @DisplayName("Truy cập GET /api/products không có token sẽ bị từ chối với mã 401 Unauthorized")
    void testGetAllProductsWithoutToken() throws Exception {
        mockMvc.perform(get("/api/products"))
                .andExpect(status().isUnauthorized())
                .andExpect(jsonPath("$.status", is(401)));
    }

    @Test
    @DisplayName("Truy cập GET /api/products với token USER hợp lệ thành công với mã 200 OK")
    void testGetAllProductsWithUserToken() throws Exception {
        String userToken = generateTestToken("student_user", List.of("ROLE_USER"));

        mockMvc.perform(get("/api/products")
                        .header("Authorization", "Bearer " + userToken))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$[0].name", is("Laptop Dell XPS 15")));
    }

    @Test
    @DisplayName("Kịch bản 1 (Thử sai): User có Role USER gọi DELETE /api/products/1 nhận mã lỗi 403 Forbidden")
    void testDeleteProductWithUserTokenForbidden() throws Exception {
        String userToken = generateTestToken("student_user", List.of("ROLE_USER"));

        mockMvc.perform(delete("/api/products/1")
                        .header("Authorization", "Bearer " + userToken))
                .andExpect(status().isForbidden())
                .andExpect(jsonPath("$.status", is(403)))
                .andExpect(jsonPath("$.error", is("Forbidden")));
    }

    @Test
    @DisplayName("Kịch bản 2 (Thử đúng): User có Role ADMIN gọi DELETE /api/products/1 thành công với mã 200 OK")
    void testDeleteProductWithAdminTokenSuccess() throws Exception {
        String adminToken = generateTestToken("admin_user", List.of("ROLE_ADMIN", "ROLE_USER"));

        mockMvc.perform(delete("/api/products/1")
                        .header("Authorization", "Bearer " + adminToken))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.status", is(200)))
                .andExpect(jsonPath("$.deletedProductId", is(1)));
    }
}
