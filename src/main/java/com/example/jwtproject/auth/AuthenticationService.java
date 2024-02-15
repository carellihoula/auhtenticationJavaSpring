package com.example.jwtproject.auth;

import com.example.jwtproject.config.JwtService;
import com.example.jwtproject.token.Token;
import com.example.jwtproject.token.TokenRepository;
import com.example.jwtproject.token.TokenType;
import com.example.jwtproject.user.Role;
import com.example.jwtproject.user.User;
import com.example.jwtproject.user.UserRepository;
import jakarta.transaction.Transactional;
import lombok.AllArgsConstructor;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;
import com.fasterxml.jackson.databind.ObjectMapper;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.springframework.http.HttpHeaders;


import java.io.IOException;
import java.util.List;

@Transactional
@Service
@AllArgsConstructor
public class AuthenticationService {
    private PasswordEncoder passwordEncoder;
    private JwtService jwtService;
    private UserRepository userRepository;
    private AuthenticationManager authenticationManager ;
    private TokenRepository tokenRepository;

    public AuthenticationResponse register(RegisterRequest request) {
        var user = User.builder()
                .firstname(request.getFirstname())
                .lastname(request.getLastname())
                .active(true)
                .email(request.getEmail())
                .password(passwordEncoder.encode(request.getPassword()))
                .role(Role.USER)
                .build();

        userRepository.save(user);
        var jwt = jwtService.generateToken(user);
        var refreshToken = jwtService.generateRefreshToken(user);
        saveUserToken(user, refreshToken);
        return AuthenticationResponse.builder()
                .accessToken(jwt)
                .refreshToken(refreshToken)
                .build();
    }

    public AuthenticationResponse authenticate(AuthenticationRequest request) {
        authenticationManager.authenticate(
                new UsernamePasswordAuthenticationToken(
                        request.getEmail(),
                        request.getPassword()
                )
        );
        var user = userRepository.findByEmail(request.getEmail()).orElseThrow(
                () -> new UsernameNotFoundException("user not found")
        );
        var jwt = jwtService.generateToken(user);
        var refreshToken = jwtService.generateRefreshToken(user);
        revokedAllValidTokenUser(user);
        saveUserToken(user, refreshToken);
        return AuthenticationResponse.builder()
                .accessToken(jwt)
                .refreshToken(refreshToken)
                .build();
    }

    public void saveUserToken(User user, String token){
        Token tokenUser = Token.builder()
                .expired(false)
                .revoked(false)
                .tokenType(TokenType.BEARER)
                .token(token)
                .user(user)
                .build();

        tokenRepository.save(tokenUser);
    }
    public void revokedAllValidTokenUser(User user){
        List<Token> allValidTokenUser = tokenRepository.findAllValidTokenUser(user.getEmail());

        if (allValidTokenUser.isEmpty()){
            return;
        }
        allValidTokenUser.forEach(tokenUser -> {
            tokenUser.setExpired(true);
            tokenUser.setRevoked(true);
        });
        tokenRepository.saveAll(allValidTokenUser);
        tokenRepository.deleteAllByExpiredAndRevoked(true, true);
    }

    public void refresh(HttpServletRequest request, HttpServletResponse response) throws IOException {
        final String authHeader = request.getHeader(HttpHeaders.AUTHORIZATION);
        final String refreshToken;
        final String userEmail;

        if(authHeader == null || !authHeader.startsWith("Bearer ")){
            return;
        }
        refreshToken = authHeader.substring(7);
        userEmail = jwtService.extractUsername(refreshToken);//extract userEmail from token;

        if(userEmail != null){
            var user = userRepository.findByEmail(userEmail).orElseThrow(
                    () -> new UsernameNotFoundException("user not found")
            );
            if(jwtService.isTokenValid(refreshToken, user)){
                var accessToken = jwtService.generateToken(user);
                var authResponse = AuthenticationResponse
                        .builder()
                        .accessToken(accessToken)
                        .refreshToken(refreshToken)
                        .build();
                //Bibliothèque jackson
                new ObjectMapper().writeValue(response.getOutputStream(), authResponse);
            }
        }
    }

}


