package com.medapp.webmedapp.controller;

import com.medapp.webmedapp.dto.payload.request.LoginRequest;
import com.medapp.webmedapp.dto.payload.request.SignupRequest;
import com.medapp.webmedapp.dto.payload.request.TokenRefreshRequest;
import com.medapp.webmedapp.dto.payload.response.JwtResponse;
import com.medapp.webmedapp.dto.payload.response.MessageResponse;
import com.medapp.webmedapp.dto.payload.response.TokenRefreshResponse;
import com.medapp.webmedapp.service.AuthService;
import jakarta.validation.Valid;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;

@CrossOrigin(origins = "http://localhost:4200", maxAge = 3600,  allowCredentials="true")
@RestController
@RequestMapping("/api/auth")
public class AuthController {

    private final AuthService authService;

    public AuthController(AuthService authService) {
        this.authService = authService;
    }

    @PostMapping("/signin")
    public ResponseEntity<?> authenticateUser(@Valid @RequestBody LoginRequest loginRequest) {
        JwtResponse jwtResponse = authService.authenticateUser(loginRequest);
        return ResponseEntity.ok(jwtResponse);
    }

    @PostMapping("/signup")
    public ResponseEntity<?> registerUser(@Valid @RequestBody SignupRequest signupRequest) {
        MessageResponse messageResponse = authService.registerUser(signupRequest);
        return ResponseEntity.ok(messageResponse);
    }

    @PostMapping("/refreshtoken")
    public ResponseEntity<?> refreshToken(@Valid @RequestBody TokenRefreshRequest request) {
        TokenRefreshResponse response = authService.refreshToken(request);
        return ResponseEntity.ok(response);
    }
}
