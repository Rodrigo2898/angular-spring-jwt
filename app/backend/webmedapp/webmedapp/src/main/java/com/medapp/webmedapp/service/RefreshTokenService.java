package com.medapp.webmedapp.service;

import com.medapp.webmedapp.entity.RefreshToken;
import com.medapp.webmedapp.exceptions.TokenRefreshException;
import com.medapp.webmedapp.repository.RefreshTokenRepository;
import com.medapp.webmedapp.repository.UsuarioRepository;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import javax.swing.text.html.Option;
import java.time.Instant;
import java.util.Optional;
import java.util.UUID;

@Service
public class RefreshTokenService {
    private final Integer refreshTokenDurationMs = 999999999;

    private final RefreshTokenRepository refreshTokenRepository;

    private final UsuarioRepository usuarioRepository;


    public RefreshTokenService(RefreshTokenRepository refreshTokenRepository, UsuarioRepository usuarioRepository) {
        this.refreshTokenRepository = refreshTokenRepository;
        this.usuarioRepository = usuarioRepository;
    }

    public Optional<RefreshToken> findByToken(String token) {
        return refreshTokenRepository.findByToken(token);
    }

    public RefreshToken createRefreshToken(Long userId) {
        RefreshToken refreshToken = new RefreshToken();

        refreshToken.setUsuario(usuarioRepository.findById(userId).get());
        refreshToken.setExpiryDate(Instant.now().plusMillis(refreshTokenDurationMs));
        refreshToken.setToken(UUID.randomUUID().toString());

       return refreshTokenRepository.save(refreshToken);
    }

    public RefreshToken verifyExpiration(RefreshToken token) {
        if (token.getExpiryDate().compareTo(Instant.now()) < 0) {
            refreshTokenRepository.delete(token);
            throw new TokenRefreshException(token.getToken(), "RefreshToken was expired. Please make a new request");
        }
        return token;
    }

    @Transactional
    public int deleteByUsuarioId(Long userId) {
        return refreshTokenRepository.deleteByUsuario(usuarioRepository.findById(userId).get());
    }
}
