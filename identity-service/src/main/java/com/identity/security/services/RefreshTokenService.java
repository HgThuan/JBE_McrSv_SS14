package com.identity.security.services;

import com.identity.dto.response.TokenResponseDTO;
import com.identity.exception.TokenRefreshException;
import com.identity.model.RefreshToken;
import com.identity.model.User;
import com.identity.repository.RefreshTokenRepository;
import com.identity.repository.UserRepository;
import com.identity.security.jwt.JwtUtils;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.time.Instant;
import java.util.Optional;
import java.util.UUID;

@Service
public class RefreshTokenService {

    @Value("${app.jwt.refresh-token-expiration}")
    private Long refreshTokenDurationMs;

    @Autowired
    private RefreshTokenRepository refreshTokenRepository;

    @Autowired
    private UserRepository userRepository;

    @Autowired
    private JwtUtils jwtUtils;

    public Optional<RefreshToken> findByToken(String token) {
        return refreshTokenRepository.findByToken(token);
    }

    /**
     * Triển khai cơ chế Token Rotation:
     * 1. Tìm RefreshToken trong DB bằng chuỗi requestToken.
     * 2. Nếu không tìm thấy hoặc token đã hết hạn (expiryDate < Instant.now()) -> Ném Exception.
     * 3. (QUAN TRỌNG - Rotation): Xóa bản ghi Refresh Token cũ khỏi DB.
     * 4. Lấy User từ token cũ, gọi JwtUtils để tạo Access Token mới.
     * 5. Gọi hàm createRefreshToken (đã viết ở Bài 1) để tạo Refresh Token hoàn toàn mới.
     * 6. Trả về cặp Token mới cho Client.
     *
     * @param requestToken Chuỗi Refresh Token do Client gửi lên
     * @return TokenResponseDTO chứa Access Token mới và Refresh Token mới
     */
    @Transactional
    public TokenResponseDTO refreshToken(String requestToken) {
        // 1. Tìm RefreshToken trong DB bằng chuỗi requestToken
        RefreshToken oldToken = refreshTokenRepository.findByToken(requestToken)
                .orElseThrow(() -> new TokenRefreshException(requestToken, "Refresh token is not in database!"));

        // 2. Nếu token đã hết hạn (expiryDate < Instant.now()) -> Xóa và ném Exception
        if (oldToken.getExpiryDate().compareTo(Instant.now()) < 0) {
            refreshTokenRepository.delete(oldToken);
            throw new TokenRefreshException(requestToken, "Refresh token was expired. Please make a new signin request");
        }

        User user = oldToken.getUser();

        // 3. (QUAN TRỌNG - Rotation): Xóa bản ghi Refresh Token cũ khỏi DB
        refreshTokenRepository.delete(oldToken);
        refreshTokenRepository.flush();

        // 4. Lấy User từ token cũ, gọi JwtUtils để tạo Access Token mới
        String newAccessToken = jwtUtils.generateAccessToken(user);

        // 5. Gọi hàm createRefreshToken để tạo Refresh Token hoàn toàn mới
        RefreshToken newRefreshToken = createRefreshToken(user.getId());

        // 6. Trả về cặp Token mới cho Client
        return new TokenResponseDTO(newAccessToken, newRefreshToken.getToken(), "Bearer");
    }

    /**
     * Sinh UUID.randomUUID(), tính toán expiryDate từ cấu hình, lưu vào DB và trả về đối tượng RefreshToken
     *
     * @param userId ID của người dùng
     * @return Đối tượng RefreshToken đã được lưu trong DB
     */
    @Transactional
    public RefreshToken createRefreshToken(Long userId) {
        User user = userRepository.findById(userId)
                .orElseThrow(() -> new RuntimeException("User not found with id: " + userId));

        // Kiểm tra xem user đã có refresh token chưa, nếu có thì tái sử dụng bản ghi để cập nhật token mới
        RefreshToken refreshToken = refreshTokenRepository.findByUser(user)
                .orElse(new RefreshToken());

        refreshToken.setUser(user);
        refreshToken.setExpiryDate(Instant.now().plusMillis(refreshTokenDurationMs));
        refreshToken.setToken(UUID.randomUUID().toString());

        return refreshTokenRepository.save(refreshToken);
    }

    /**
     * Kiểm tra xem token đã quá hạn so với thời gian hiện tại chưa.
     * Nếu đã hết hạn, xóa token khỏi DB và ném ra TokenRefreshException.
     *
     * @param token RefreshToken cần kiểm tra
     * @return RefreshToken hợp lệ
     */
    @Transactional
    public RefreshToken verifyExpiration(RefreshToken token) {
        if (token.getExpiryDate().compareTo(Instant.now()) < 0) {
            refreshTokenRepository.delete(token);
            throw new TokenRefreshException(token.getToken(),
                    "Refresh token was expired. Please make a new signin request");
        }

        return token;
    }

    @Transactional
    public int deleteByUserId(Long userId) {
        return userRepository.findById(userId)
                .map(user -> refreshTokenRepository.deleteByUser(user))
                .orElse(0);
    }
}
