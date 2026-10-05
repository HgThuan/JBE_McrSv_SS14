package com.identity.security.services;

import com.identity.repository.RefreshTokenRepository;
import com.identity.repository.UserRepository;
import com.identity.security.jwt.JwtUtils;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.data.redis.core.StringRedisTemplate;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.util.Date;
import java.util.concurrent.TimeUnit;

@Service
public class TokenBlacklistService {

    private static final Logger logger = LoggerFactory.getLogger(TokenBlacklistService.class);

    @Autowired
    private StringRedisTemplate redisTemplate;

    @Autowired
    private JwtUtils jwtUtils;

    @Autowired
    private UserRepository userRepository;

    @Autowired
    private RefreshTokenRepository refreshTokenRepository;

    /**
     * Thực hiện thu hồi Access Token và lưu vào Blacklist của Redis:
     * 1. Giải mã token để lấy claim "jti" và "exp" (thời gian hết hạn).
     * 2. Tính toán TTL (Time-To-Live): TTL = exp - thời gian hiện tại.
     * 3. Lưu key "blacklist:{jti}" vào Redis với giá trị "revoked".
     * 4. Thiết lập thời gian tự động xóa (Expiration) cho key này trong Redis bằng đúng TTL.
     * 5. (Tùy chọn): Xóa luôn Refresh Token tương ứng trong PostgreSQL.
     *
     * @param token Chuỗi Access Token cần thu hồi
     */
    @Transactional
    public void logout(String token) {
        // 1. Giải mã token để lấy claim "jti" và "exp" (thời gian hết hạn)
        String jti = jwtUtils.getJtiFromJwtToken(token);
        Date exp = jwtUtils.getExpirationFromJwtToken(token);

        if (jti == null || exp == null) {
            logger.warn("Token không chứa jti hoặc expiration hợp lệ!");
            return;
        }

        // 2. Tính toán TTL (Time-To-Live): TTL = exp - thời gian hiện tại
        long now = System.currentTimeMillis();
        long ttl = exp.getTime() - now;

        if (ttl > 0) {
            // 3. Lưu key "blacklist:{jti}" vào Redis với giá trị "revoked"
            // 4. Thiết lập thời gian tự động xóa (Expiration) cho key này trong Redis bằng đúng TTL
            String redisKey = "blacklist:" + jti;
            redisTemplate.opsForValue().set(redisKey, "revoked", ttl, TimeUnit.MILLISECONDS);
            logger.info(">>> Đã lưu token vào Redis Blacklist: key='{}', TTL={} ms ({} giây)",
                    redisKey, ttl, ttl / 1000);
        }

        // 5. (Tùy chọn): Xóa luôn Refresh Token tương ứng trong PostgreSQL
        try {
            String username = jwtUtils.getUserNameFromJwtToken(token);
            userRepository.findByUsername(username).ifPresent(user -> {
                refreshTokenRepository.deleteByUser(user);
                logger.info(">>> Đã xóa Refresh Token trong PostgreSQL cho user: {}", username);
            });
        } catch (Exception e) {
            logger.warn("Không thể xóa Refresh Token trong PostgreSQL khi logout: {}", e.getMessage());
        }
    }

    /**
     * Kiểm tra xem token đã bị đưa vào Blacklist của Redis hay chưa
     */
    public boolean isTokenBlacklisted(String token) {
        try {
            String jti = jwtUtils.getJtiFromJwtToken(token);
            if (jti != null) {
                Boolean exists = redisTemplate.hasKey("blacklist:" + jti);
                return Boolean.TRUE.equals(exists);
            }
        } catch (Exception e) {
            logger.error("Lỗi khi kiểm tra Blacklist trong Redis: {}", e.getMessage());
        }
        return false;
    }
}
