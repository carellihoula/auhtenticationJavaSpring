package com.example.jwtproject.token;

import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.Query;

import java.util.List;
import java.util.Optional;

public interface TokenRepository extends JpaRepository<Token, Integer> {
    Optional<Token> findByToken(String token);

    @Query("FROM Token t INNER JOIN User u " +
            "ON t.user.id = u.id " +
            "WHERE u.email = :email AND (t.expired = false AND t.revoked = false)")
    List<Token> findAllValidTokenUser(String email);

    void deleteAllByExpiredAndRevoked(boolean expire, boolean revoked);

}
