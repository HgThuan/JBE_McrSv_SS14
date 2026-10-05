package com.gateway;

import com.gateway.filter.JwtBlacklistGlobalFilter;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;

import static org.assertj.core.api.Assertions.assertThat;

@SpringBootTest
class GatewayServiceApplicationTests {

    @Autowired
    private JwtBlacklistGlobalFilter filter;

    @Test
    @DisplayName("Kiểm tra Gateway context tải thành công và JwtBlacklistGlobalFilter đã được inject")
    void contextLoads() {
        assertThat(filter).isNotNull();
    }
}
