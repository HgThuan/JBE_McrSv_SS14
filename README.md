# Session 14: Kiến Trúc Microservices Security & Quản Lý Phiên Nâng Cao (Spring Boot 3, JJWT 0.11.5, PostgreSQL, Redis & Spring Cloud Gateway)

Dự án này bao gồm đầy đủ 5 bài thực hành bảo mật phân tán từ cơ bản đến nâng cao trong hệ sinh thái Microservices của Spring Boot 3 & Spring Cloud:

1. **`identity-service` (Authentication Server - Port 8085)**:
   - Cấp phát cặp đôi **Access Token (JWT - TTL 15 phút)** và **Refresh Token (UUID - TTL 7 ngày)**.
   - Quản lý trạng thái Refresh Token trong cơ sở dữ liệu **PostgreSQL** (Port 5433).
   - **Token Rotation**: Tự động hủy Refresh Token cũ và cấp Refresh Token mới khi làm mới phiên để chống Replay Attack (Bài 3).
   - **JWT Blacklist (Redis - Port 6379)**: Gán định danh `jti` (JWT ID) cho mỗi Access Token; khi Logout, lưu `blacklist:{jti}` vào Redis với thời gian sống bằng đúng TTL còn lại của Token để vô hiệu hóa tức thì (Bài 4).
2. **`product-service` (Resource Server - Port 8086)**:
   - **Không có Database** User, hoàn toàn tin tưởng vào chữ ký JWT dùng chung Secret Key.
   - Phân quyền mức Method bằng `@EnableMethodSecurity` và `@PreAuthorize("hasRole('ADMIN')")` (Bài 2).
3. **`gateway-service` (API Gateway & Centralized Security - Port 8088)**:
   - Sử dụng **Spring Cloud Gateway (WebFlux / Non-blocking)** làm cửa ngõ duy nhất đón nhận request.
   - Triển khai **Global Filter (`JwtBlacklistGlobalFilter`)** tích hợp **Reactive Redis (`ReactiveStringRedisTemplate`)**.
   - Kiểm tra `blacklist:{jti}` ngay tại "cửa ngõ" Gateway: nếu token đã logout, chặn đứng tức thì với HTTP `401 Unauthorized` mà **không chuyển tiếp (forward)** request vào các service phía sau, giúp tối ưu tài nguyên và bảo vệ hệ thống triệt để (Bài 5).

---

## 1. Mô Hình Kiến Trúc Bảo Mật Toàn Diện (Microservices Centralized Security)

```mermaid
sequenceDiagram
    autonumber
    actor Client
    participant GW as Gateway-Service (Port 8088)
    participant Auth as Identity-Service (Port 8085)
    participant PG as PostgreSQL (Port 5433)
    participant Redis as Redis (Port 6379)
    participant Res as Product-Service (Port 8086)

    Note over Client, Res: [Phần 1: Đăng nhập qua Gateway & Cấp phát Token Đôi]
    Client->>GW: POST /api/auth/login { username, password }
    GW->>Auth: Forward đến Identity-Service
    Auth->>PG: Xác thực user trong bảng users
    Auth->>Auth: Gán claim jti (UUID) vào Access Token (A)
    Auth->>PG: Lưu Refresh Token (R1) vào bảng refresh_tokens
    Auth-->>GW: Trả về { accessToken: A (chứa jti), refreshToken: R1 }
    GW-->>Client: Trả về cặp Token cho Client

    Note over Client, Res: [Phần 2: Token Rotation khi gia hạn phiên]
    Client->>GW: POST /api/auth/refresh { refreshToken: R1 }
    GW->>Auth: Forward đến Identity-Service
    Auth->>PG: Xóa R1 khỏi Database
    Auth->>Auth: Tạo Access Token mới (B)
    Auth->>PG: Lưu Refresh Token mới (R2)
    Auth-->>GW-->>Client: Trả về { accessToken: B, refreshToken: R2 }
    Client->>GW: Replay R1 -> Auth kiểm tra DB -> Trả về 403 Forbidden!

    Note over Client, Res: [Phần 3: Gọi Resource Server thành công khi Token hợp lệ]
    Client->>GW: GET /api/products (Header: Bearer Token A)
    GW->>Redis: Reactive check: EXISTS blacklist:{jti}? -> false
    GW->>Res: Forward đến Product-Service (Port 8086)
    Res->>Res: Xác thực chữ ký JWT & phân quyền Role
    Res-->>GW-->>Client: 200 OK (Danh sách sản phẩm)

    Note over Client, Res: [Phần 4: Logout qua Gateway & Đưa Token vào Redis Blacklist]
    Client->>GW: POST /api/auth/logout (Header: Bearer Token A)
    GW->>Auth: Forward đến Identity-Service
    Auth->>Auth: Trích xuất jti và exp; tính TTL = exp - now
    Auth->>Redis: SET blacklist:{jti} "revoked" EX TTL
    Auth->>PG: Xóa Refresh Token của user tương ứng
    Auth-->>GW-->>Client: 200 OK (Đăng xuất thành công)

    Note over Client, Res: [Phần 5: Centralized Security - Gateway chặn đứng Token đã Logout]
    Client->>GW: GET /api/products (Header: Bearer Token A vừa logout)
    GW->>Redis: Reactive check: EXISTS blacklist:{jti}? -> true!
    GW-->>Client: 401 Unauthorized (Chặn ngay tại Gateway!)
    Note over Res: Request KHÔNG BAO GIỜ chạm tới Product-Service
```

---

## 2. Cấu Trúc Mã Nguồn Dự Án (Multi-Module Maven)

```
SS14/
├── docker-compose.yml              # Container PostgreSQL (5433) & Redis (6379)
├── pom.xml                         # Aggregator Root POM (quản lý cả 3 services)
├── postman_collection.json         # Postman collection đầy đủ kịch bản 5 bài
├── README.md                       # Hướng dẫn chi tiết dự án
│
├── identity-service/               # Authentication & Token Management Service (Port 8085)
│   ├── pom.xml                     # spring-boot-starter-data-redis, postgresql, jjwt
│   └── src/
│       ├── main/java/com/identity/
│       │   ├── config/DataInitializer.java         # Tạo sẵn admin/password123, user/password123
│       │   ├── controller/AuthController.java      # /login, /refresh, /logout
│       │   ├── controller/TestController.java
│       │   ├── dto/
│       │   ├── exception/
│       │   ├── model/RefreshToken.java
│       │   ├── model/User.java
│       │   ├── repository/
│       │   ├── security/WebSecurityConfig.java
│       │   ├── security/jwt/
│       │   │   ├── AuthEntryPointJwt.java
│       │   │   ├── AuthTokenFilter.java            # Kiểm tra Redis Blacklist nội bộ
│       │   │   └── JwtUtils.java                   # Sinh token có JTI, trích xuất exp, jti
│       │   └── security/services/
│       │       ├── RefreshTokenService.java        # Quản lý Token Rotation (Bài 3)
│       │       └── TokenBlacklistService.java      # Quản lý Blacklist Redis với TTL (Bài 4)
│       └── main/resources/application.yml          # Cấu hình PostgreSQL (5433) & Redis (6379)
│
├── product-service/                # Resource Server tiêu thụ Token (Port 8086)
│   ├── pom.xml                     # KHÔNG có Database, Spring Security + JJWT
│   └── src/
│       ├── main/java/com/product/
│       │   ├── controller/ProductController.java  # @PreAuthorize("hasRole('ADMIN')")
│       │   ├── exception/
│       │   ├── model/Product.java
│       │   ├── security/JwtAuthenticationFilter.java
│       │   ├── security/JwtUtils.java
│       │   └── security/SecurityConfig.java       # @EnableMethodSecurity
│       └── main/resources/application.yml
│
└── gateway-service/                # Spring Cloud Gateway & Centralized Security (Port 8088)
    ├── pom.xml                     # spring-cloud-starter-gateway, spring-boot-starter-data-redis-reactive
    └── src/
        ├── main/java/com/gateway/
        │   ├── filter/
        │   │   └── JwtBlacklistGlobalFilter.java  # GlobalFilter WebFlux kiểm tra Redis Blacklist
        │   └── GatewayServiceApplication.java
        └── main/resources/application.yml          # Route định tuyến đến 8085 và 8086
```

---

## 3. Hướng Dẫn Cài Đặt & Chạy Toàn Bộ Hệ Thống

### Bước 1: Khởi động cơ sở dữ liệu (PostgreSQL & Redis)
- **PostgreSQL**: Chạy qua `docker compose up -d` (cổng máy chủ: `5433`).
- **Redis**: Chạy qua docker trên cổng `6379`.

### Bước 2: Build toàn bộ dự án & chạy Automated Tests
```bash
cd /home/THUANHV2/Dev/JBE/SS14
mvn clean test
```
> Tất cả 13 bài unit/integration test sẽ chạy tự động và đảm bảo đạt `BUILD SUCCESS` (0 failures, 0 errors).

### Bước 3: Đóng gói và Khởi chạy 3 Services
```bash
mvn package -DskipTests
```
Mở 3 cửa sổ terminal riêng biệt:
- **Terminal 1 (`identity-service` - Port 8085)**:
  ```bash
  java -jar identity-service/target/identity-service-0.0.1-SNAPSHOT.jar
  ```
- **Terminal 2 (`product-service` - Port 8086)**:
  ```bash
  java -jar product-service/target/product-service-0.0.1-SNAPSHOT.jar
  ```
- **Terminal 3 (`gateway-service` - Port 8088)**:
  ```bash
  java -jar gateway-service/target/gateway-service-0.0.1-SNAPSHOT.jar
  ```

---

## 4. Hướng Dẫn Kiểm Thử Từng Kịch Bản (CURL & Postman)

### 🔹 Kịch bản 1: Cấp phát cặp Token Đôi (Bài 1)
```bash
curl -X POST http://localhost:8088/api/auth/login \
  -H "Content-Type: application/json" \
  -d '{"username": "admin", "password": "password123"}'
```
- Trả về `accessToken` (JWT chứa `jti`, thời hạn 15 phút) và `refreshToken` (UUID ngẫu nhiên, lưu trong bảng `refresh_tokens` của PostgreSQL).

### 🔹 Kịch bản 2: Phân quyền Method Security tại Resource Server (Bài 2)
1. Gọi lấy danh sách sản phẩm với User Token:
   ```bash
   curl -H "Authorization: Bearer <USER_ACCESS_TOKEN>" http://localhost:8088/api/products
   ```
   👉 Trả về `200 OK` và danh sách sản phẩm.
2. User thường cố gắng xóa sản phẩm (`DELETE`):
   ```bash
   curl -X DELETE -H "Authorization: Bearer <USER_ACCESS_TOKEN>" http://localhost:8088/api/products/1
   ```
   👉 Trả về `403 Forbidden` (`Bạn không có quyền thực hiện hành động này! Cần quyền ADMIN`).
3. Admin thực hiện xóa sản phẩm:
   ```bash
   curl -X DELETE -H "Authorization: Bearer <ADMIN_ACCESS_TOKEN>" http://localhost:8088/api/products/1
   ```
   👉 Trả về `200 OK` (`Đã xóa sản phẩm thành công với id: 1`).

### 🔹 Kịch bản 3: Token Rotation Flow (3 Bước) (Bài 3)
1. **Bước 1**: Đăng nhập lấy Token A và Refresh Token R1.
2. **Bước 2**: Gửi R1 vào `/api/auth/refresh`:
   ```bash
   curl -X POST http://localhost:8088/api/auth/refresh \
     -H "Content-Type: application/json" \
     -d '{"refreshToken": "<R1>"}'
   ```
   👉 Nhận Access Token mới B và Refresh Token mới R2. R1 bị xóa vĩnh viễn khỏi PostgreSQL.
3. **Bước 3 (Replay Attack)**: Gửi lại R1 cũ một lần nữa:
   ```bash
   curl -X POST http://localhost:8088/api/auth/refresh \
     -H "Content-Type: application/json" \
     -d '{"refreshToken": "<R1>"}'
   ```
   👉 Trả về `403 Forbidden` (`Refresh Token không tồn tại trong hệ thống! Vui lòng đăng nhập lại.`).

### 🔹 Kịch bản 4: Logout tức thì với Redis Blacklist & TTL (Bài 4)
1. Gọi API Logout:
   ```bash
   curl -X POST http://localhost:8088/api/auth/logout \
     -H "Authorization: Bearer <ACCESS_TOKEN>"
   ```
2. Kiểm tra Redis key và TTL:
   ```bash
   docker exec koshin-redis-1 redis-cli KEYS "blacklist:*"
   docker exec koshin-redis-1 redis-cli TTL "blacklist:<jti>"
   ```
   👉 Key `blacklist:<jti>` được tạo với TTL đếm ngược chính xác theo thời gian còn lại của Access Token.

### 🔹 Kịch bản 5: Centralized Security tại API Gateway (Bài 5)
1. **Truy cập trước khi Logout qua Gateway**:
   ```bash
   curl -i -H "Authorization: Bearer <ACCESS_TOKEN>" http://localhost:8088/api/products
   ```
   👉 Gateway kiểm tra Redis không thấy JTI trong Blacklist -> Chuyển tiếp request đến `product-service` -> Trả về `200 OK`.

2. **Thực hiện Logout**:
   ```bash
   curl -X POST http://localhost:8088/api/auth/logout \
     -H "Authorization: Bearer <ACCESS_TOKEN>"
   ```

3. **Truy cập sau khi Logout qua Gateway**:
   ```bash
   curl -i -H "Authorization: Bearer <ACCESS_TOKEN>" http://localhost:8088/api/products
   ```
   👉 **Kết quả:** Gateway bắt được JTI trong Redis Blacklist, ngay lập tức trả về HTTP `401 Unauthorized`:
   ```json
   {
     "status": 401,
     "error": "Unauthorized",
     "message": "Access Token đã bị thu hồi (Blacklisted tại Gateway)! Vui lòng đăng nhập lại.",
     "path": "/api/products"
   }
   ```
   👉 Quan sát log của `product-service`: Không hề phát sinh bất kỳ request hay overhead nào, chứng minh Gateway đã bảo vệ hệ thống ngay tại "cửa ngõ".

---

## 5. Sử Dụng Postman Collection

File `postman_collection.json` đã được tích hợp sẵn đầy đủ 5 thư mục và các script tự động trích xuất Token (`pm.environment.set`):
1. Import file `postman_collection.json` vào Postman.
2. Chạy lần lượt các request theo thứ tự đánh số:
   - `1. Authentication & Tokens (Identity-Service)`
   - `2. JWT Blacklist Flow (Redis & Logout Tức Thì)`
   - `3. Token Rotation Flow (3 Bước Kiểm Thử)`
   - `4. Product-Service Resource Server (Port 8086)`
   - `5. API Gateway (Port 8088 - Centralized Security)`
3. Tất cả các assertion test trong Postman sẽ chuyển sang màu xanh lá (`PASS`).
