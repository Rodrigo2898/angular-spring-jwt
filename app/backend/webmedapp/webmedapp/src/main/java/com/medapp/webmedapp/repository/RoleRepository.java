package com.medapp.webmedapp.repository;

import com.medapp.webmedapp.entity.Role;
import com.medapp.webmedapp.entity.enums.ERole;
import org.springframework.stereotype.Repository;

import java.util.Optional;

@Repository
public interface RoleRepository extends BaseRepository<Role, Long> {
    Optional<Role> findByName(ERole name);
}
