package com.product.controller;

import com.product.model.Product;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.web.bind.annotation.*;

import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.concurrent.CopyOnWriteArrayList;

@CrossOrigin(origins = "*", maxAge = 3600)
@RestController
@RequestMapping("/api/products")
public class ProductController {

    // Danh sách sản phẩm tĩnh (in-memory) để phục vụ bài học Security
    private final List<Product> productList = new CopyOnWriteArrayList<>(List.of(
            new Product(1L, "Laptop Dell XPS 15", 1500.0, "High-end developer laptop"),
            new Product(2L, "MacBook Pro M3", 2000.0, "Apple M3 Pro silicon chip"),
            new Product(3L, "Bàn phím cơ Keychron K2", 90.0, "Wireless Mechanical Keyboard"),
            new Product(4L, "Màn hình Dell UltraSharp 27 inch", 450.0, "4K IPS Monitor")
    ));

    /**
     * GET /api/products
     * Cho phép mọi user đã đăng nhập (bất kể vai trò USER hay ADMIN) truy cập.
     */
    @GetMapping
    @PreAuthorize("isAuthenticated()")
    public ResponseEntity<List<Product>> getAllProducts() {
        return ResponseEntity.ok(productList);
    }

    /**
     * DELETE /api/products/{id}
     * Chỉ cho phép User có Role ADMIN (ROLE_ADMIN) thực hiện.
     */
    @DeleteMapping("/{id}")
    @PreAuthorize("hasRole('ADMIN')")
    public ResponseEntity<?> deleteProduct(@PathVariable Long id) {
        boolean removed = productList.removeIf(product -> product.getId().equals(id));

        Map<String, Object> response = new HashMap<>();
        if (removed) {
            response.put("status", 200);
            response.put("message", "Đã xóa sản phẩm thành công với id: " + id);
            response.put("deletedProductId", id);
            return ResponseEntity.ok(response);
        } else {
            response.put("status", 404);
            response.put("message", "Không tìm thấy sản phẩm với id: " + id);
            return ResponseEntity.status(HttpStatus.NOT_FOUND).body(response);
        }
    }
}
