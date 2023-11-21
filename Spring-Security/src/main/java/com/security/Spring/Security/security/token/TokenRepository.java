package com.security.Spring.Security.security.token;

import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.Query;

import java.util.List;
import java.util.Optional;

public interface TokenRepository extends JpaRepository<Token, Integer> {
    @Query(value = """
        select t from Token  t inner join  AppUser  apuser
        on t.appUser.id = apuser.id
        where  apuser.id = :id and (t.isExpired = false or t.isRevoked = false )
        """)
    List<Token> finalAllValidTokenByUser(Integer id);
    Optional<Token> findByAccessToken(String accessToken);
}
