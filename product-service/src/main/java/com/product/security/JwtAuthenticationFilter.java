package com.product.security;

import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.web.authentication.WebAuthenticationDetailsSource;
import org.springframework.stereotype.Component;
import org.springframework.util.StringUtils;
import org.springframework.web.filter.OncePerRequestFilter;

import java.io.IOException;
import java.util.List;
import java.util.stream.Collectors;

@Component
public class JwtAuthenticationFilter extends OncePerRequestFilter {

    private static final Logger logger = LoggerFactory.getLogger(JwtAuthenticationFilter.class);

    @Autowired
    private JwtUtils jwtUtils;

    @Override
    protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response, FilterChain filterChain)
            throws ServletException, IOException {
        try {
            // 1. Lấy chuỗi JWT từ Header "Authorization: Bearer <token>"
            String jwt = parseJwt(request);

            // 2. Sử dụng JJWT 0.11.5 để verify chữ ký (dùng chung Secret Key với Identity-Service)
            if (jwt != null && jwtUtils.validateJwtToken(jwt)) {

                // 3. Nếu hợp lệ, trích xuất "username" và "roles" từ Claims
                String username = jwtUtils.getUsernameFromJwtToken(jwt);
                List<String> roles = jwtUtils.getRolesFromJwtToken(jwt);

                // 4. Chuyển đổi Roles (ví dụ: ["ADMIN"] hoặc ["ROLE_ADMIN"]) thành danh sách SimpleGrantedAuthority
                List<SimpleGrantedAuthority> authorities = roles.stream()
                        .map(role -> role.startsWith("ROLE_") ? new SimpleGrantedAuthority(role) : new SimpleGrantedAuthority("ROLE_" + role))
                        .collect(Collectors.toList());

                // 5. Tạo đối tượng UsernamePasswordAuthenticationToken và nạp vào SecurityContextHolder
                UsernamePasswordAuthenticationToken authentication =
                        new UsernamePasswordAuthenticationToken(username, null, authorities);
                authentication.setDetails(new WebAuthenticationDetailsSource().buildDetails(request));

                SecurityContextHolder.getContext().setAuthentication(authentication);
                logger.debug("Authenticated user '{}' with roles: {}", username, authorities);
            }
        } catch (Exception e) {
            logger.error("Cannot set user authentication in Product-Service: {}", e.getMessage());
        }

        filterChain.doFilter(request, response);
    }

    private String parseJwt(HttpServletRequest request) {
        String headerAuth = request.getHeader("Authorization");

        if (StringUtils.hasText(headerAuth) && headerAuth.startsWith("Bearer ")) {
            return headerAuth.substring(7);
        }

        return null;
    }
}
