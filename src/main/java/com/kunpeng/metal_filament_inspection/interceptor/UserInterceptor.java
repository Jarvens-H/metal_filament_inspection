package com.kunpeng.metal_filament_inspection.interceptor;


import com.kunpeng.metal_filament_inspection.utils.JwtUtil;
import com.kunpeng.metal_filament_inspection.utils.UserHolder;
import io.jsonwebtoken.Claims;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import lombok.extern.slf4j.Slf4j;
import org.springframework.lang.Nullable;
import org.springframework.web.servlet.HandlerInterceptor;
@Slf4j
public class UserInterceptor implements HandlerInterceptor {
    private final JwtUtil jwtUtil;
    public UserInterceptor(JwtUtil jwtUtil) {
        this.jwtUtil = jwtUtil;
    }
    @Override
    public boolean preHandle(HttpServletRequest request, HttpServletResponse response, Object handler) throws Exception {
        // 1.获取请求头中的 token
        String token = request.getHeader("authorization");
        if (token == null || token.isBlank()) {
            // 空值放行
            return true;
        }
        // 2.校验token
        Claims claims = jwtUtil.parseToken(token);
        // 3.存入上下文
        UserHolder.saveUser(claims.get("userId",Long.class));
        // 4.放行
        return true;
    }

    @Override
    public void afterCompletion(HttpServletRequest request, HttpServletResponse response, Object handler, @Nullable Exception ex) throws Exception {
        UserHolder.removeUser();
    }
}
