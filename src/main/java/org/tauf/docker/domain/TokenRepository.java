package org.tauf.docker.domain;

import org.springframework.data.jpa.repository.JpaRepository;

import java.util.List;

public interface TokenRepository extends JpaRepository<Token, String> {
    List<Token> findByUsername(String user);
}
