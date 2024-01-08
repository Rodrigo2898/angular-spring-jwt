package com.medapp.webmedapp.repository;

import com.medapp.webmedapp.entity.RefreshToken;
import com.medapp.webmedapp.entity.Usuario;
import org.springframework.data.jpa.repository.Modifying;
import org.springframework.stereotype.Repository;

import java.util.Optional;

@Repository
public interface RefreshTokenRepository extends BaseRepository<RefreshToken, Long> {
    Optional<RefreshToken> findByToken(String token);

    @Modifying
    int deleteByUsuario(Usuario usuario);
}
