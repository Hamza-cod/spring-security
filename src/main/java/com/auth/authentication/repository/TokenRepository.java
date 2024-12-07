package com.auth.authentication.repository;

import com.auth.authentication.entity.Token;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.Modifying;
import org.springframework.data.jpa.repository.Query;
import org.springframework.data.repository.query.Param;
import org.springframework.stereotype.Repository;

import java.util.Optional;

@Repository
public interface TokenRepository extends JpaRepository<Token,Long> {
    @Query("""
            select t.id from Token t
            where t.user.id = :userId and type = ACCESS_TOKEN
            """)
    Optional<Long> findByUserId(@Param("userId") Long userId);
    @Query("""
            select t.id from Token t
            where t.user.id = :userId and type = REFRESH_TOKEN
            """)
    Optional<Long> findRefreshTokenByUserId(@Param("userId") Long userId);

    @Query("""
             select t.ID from Token t
            where t.token = :token
            """)
    Optional<Long> findByToken(@Param("token") String token);
    @Query("""
             select t from Token t
            where t.token = :token
            """)
    Optional<Token> findOneByToken(@Param("token") String token);

    @Modifying
    @Query("""
            DELETE FROM Token t
            WHERE t.id = :id
            """)
    void deleteOneById(@Param("id") Long id);
}
