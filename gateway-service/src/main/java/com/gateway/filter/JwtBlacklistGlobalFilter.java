package com.gateway.filter;

import io.jsonwebtoken.Claims;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.security.Keys;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.cloud.gateway.filter.GatewayFilterChain;
import org.springframework.cloud.gateway.filter.GlobalFilter;
import org.springframework.core.Ordered;
import org.springframework.core.io.buffer.DataBuffer;
import org.springframework.data.redis.core.ReactiveStringRedisTemplate;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpStatus;
import org.springframework.http.MediaType;
import org.springframework.http.server.reactive.ServerHttpResponse;
import org.springframework.stereotype.Component;
import org.springframework.util.StringUtils;
import org.springframework.web.server.ServerWebExchange;
import reactor.core.publisher.Mono;

import java.nio.charset.StandardCharsets;
import java.security.Key;

@Component
public class JwtBlacklistGlobalFilter implements GlobalFilter, Ordered {

    private static final Logger logger = LoggerFactory.getLogger(JwtBlacklistGlobalFilter.class);

    @Autowired
    private ReactiveStringRedisTemplate redisTemplate;

    @Value("${app.jwt.secret}")
    private String jwtSecret;

    private Key key() {
        return Keys.hmacShaKeyFor(jwtSecret.getBytes(StandardCharsets.UTF_8));
    }

    @Override
    public Mono<Void> filter(ServerWebExchange exchange, GatewayFilterChain chain) {
        String path = exchange.getRequest().getURI().getPath();

        // 1. Trích xuất Token từ Header "Authorization"
        String authHeader = exchange.getRequest().getHeaders().getFirst(HttpHeaders.AUTHORIZATION);

        if (!StringUtils.hasText(authHeader) || !authHeader.startsWith("Bearer ")) {
            // Không có token -> Chuyển tiếp để service bên trong tự xử lý quyền truy cập
            return chain.filter(exchange);
        }

        String token = authHeader.substring(7);

        // 2. Parse JWT (không cần check DB, chỉ cần parse để lấy "jti")
        final String jti;
        try {
            Claims claims = Jwts.parserBuilder()
                    .setSigningKey(key())
                    .build()
                    .parseClaimsJws(token)
                    .getBody();

            String extractedJti = claims.getId();
            if (extractedJti == null) {
                extractedJti = (String) claims.get("jti");
            }
            jti = extractedJti;
        } catch (Exception e) {
            logger.warn("JWT không hợp lệ hoặc đã hết hạn tại Gateway: {}", e.getMessage());
            return onError(exchange, HttpStatus.UNAUTHORIZED, "Access Token không hợp lệ hoặc đã hết hạn!");
        }

        if (jti == null) {
            return chain.filter(exchange);
        }

        // 3. Truy vấn Redis bằng ReactiveRedisTemplate (sử dụng non-blocking flatMap)
        return redisTemplate.hasKey("blacklist:" + jti)
                .flatMap(isBlacklisted -> {
                    // 4. Nếu tồn tại trong Redis: Trả về lỗi 401 Unauthorized ngay lập tức
                    if (Boolean.TRUE.equals(isBlacklisted)) {
                        logger.warn(">>> [Gateway Chặn] Token chứa JTI '{}' đã nằm trong Blacklist (User đã Logout) khi truy cập '{}'",
                                jti, path);
                        return onError(exchange, HttpStatus.UNAUTHORIZED,
                                "Access Token đã bị thu hồi (Blacklisted tại Gateway)! Vui lòng đăng nhập lại.");
                    }

                    // 5. Nếu không: chain.filter(exchange) tiếp tục chuyển tiếp request
                    return chain.filter(exchange);
                });
    }

    private Mono<Void> onError(ServerWebExchange exchange, HttpStatus status, String message) {
        ServerHttpResponse response = exchange.getResponse();
        response.setStatusCode(status);
        response.getHeaders().setContentType(MediaType.APPLICATION_JSON);

        String body = String.format(
                "{\"status\":%d,\"error\":\"Unauthorized\",\"message\":\"%s\",\"path\":\"%s\"}",
                status.value(), message, exchange.getRequest().getURI().getPath());

        DataBuffer buffer = response.bufferFactory().wrap(body.getBytes(StandardCharsets.UTF_8));
        return response.writeWith(Mono.just(buffer));
    }

    @Override
    public int getOrder() {
        return -1; // Ưu tiên chạy sớm nhất trước các filter khác
    }
}
