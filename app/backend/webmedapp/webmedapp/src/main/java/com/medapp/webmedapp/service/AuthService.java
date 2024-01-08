package com.medapp.webmedapp.service;

import com.medapp.webmedapp.config.security.jwt.JwtUtils;
import com.medapp.webmedapp.dto.payload.request.LoginRequest;
import com.medapp.webmedapp.dto.payload.request.SignupRequest;
import com.medapp.webmedapp.dto.payload.response.JwtResponse;
import com.medapp.webmedapp.dto.payload.response.MessageResponse;
import com.medapp.webmedapp.entity.Role;
import com.medapp.webmedapp.entity.UserDetailsImpl;
import com.medapp.webmedapp.entity.Usuario;
import com.medapp.webmedapp.entity.enums.ERole;
import com.medapp.webmedapp.repository.RoleRepository;
import com.medapp.webmedapp.repository.UsuarioRepository;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;

import java.util.HashSet;
import java.util.List;
import java.util.Set;

@Service
public class AuthService {

    private final AuthenticationManager authenticationManager;
    private final UsuarioRepository usuarioRepository;
    private final RoleRepository roleRepository;
    private final PasswordEncoder passwordEncoder= new BCryptPasswordEncoder();
    private final JwtUtils jwtUtils;


    public AuthService(AuthenticationManager authenticationManager, UsuarioRepository usuarioRepository,
                       RoleRepository roleRepository, JwtUtils jwtUtils) {
        this.authenticationManager = authenticationManager;
        this.usuarioRepository = usuarioRepository;
        this.roleRepository = roleRepository;
        this.jwtUtils = jwtUtils;
    }

    public JwtResponse authenticateUser(LoginRequest loginRequest) {
        Authentication authentication = authenticationManager.authenticate(
                new UsernamePasswordAuthenticationToken(
                        loginRequest.getUsername(),
                        loginRequest.getPassword()
                )
        );

        SecurityContextHolder.getContext().setAuthentication(authentication);
        String jwt = jwtUtils.generateJwtToken(authentication);

        UserDetailsImpl userDetails = (UserDetailsImpl) authentication.getPrincipal();
        List<String> roles = userDetails.getAuthorities().stream()
                .map(GrantedAuthority::getAuthority)
                .toList();

        return new JwtResponse(
                jwt,
                userDetails.getId(),
                userDetails.getUsername(),
                userDetails.getEmail(),
                roles
        );
    }

    public MessageResponse registerUser(SignupRequest signupRequest) {
        if (usuarioRepository.existsByUsername(signupRequest.getUsername())) {
            return new MessageResponse("Error: Username already existis");
        }

        if (usuarioRepository.existsByEmail(signupRequest.getEmail())) {
            return new MessageResponse("Error: Email already in use");
        }

        // Criando novo usuário
        Usuario usuario = new Usuario(
                signupRequest.getUsername(),
                signupRequest.getEmail(),
                passwordEncoder.encode(signupRequest.getPassword())
        );

        Set<String> strRoles = signupRequest.getRole();
        Set<Role> roles = new HashSet<>();

        if (strRoles == null) {
            Role userRole = roleRepository.findByName(ERole.ROLE_USER)
                    .orElseThrow(() -> new RuntimeException("Error: role is not found"));
            roles.add(userRole);
        } else {
            strRoles.forEach(role -> {
                switch (role) {
                    case "admin":
                        Role adminRole = roleRepository.findByName(ERole.ROLE_ADMIN)
                                .orElseThrow(() -> new RuntimeException("Error: role is not found"));
                        roles.add(adminRole);

                        break;
                    case "mod":
                        Role modRole = roleRepository.findByName(ERole.ROLE_MODERATOR)
                                .orElseThrow(() -> new RuntimeException("Error: role is not found"));
                        roles.add(modRole);

                        break;
                    default:
                        Role userRole = roleRepository.findByName(ERole.ROLE_USER)
                                .orElseThrow(() -> new RuntimeException("Error: role is not found"));
                        roles.add(userRole);
                }
            });
        }
        usuario.setRoles(roles);
        usuarioRepository.save(usuario);

        return new MessageResponse("Usuário registrado com sucesso");
    }
}
