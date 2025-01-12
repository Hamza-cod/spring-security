package com.auth.authentication.entity;

import com.fasterxml.jackson.annotation.JsonBackReference;
import jakarta.persistence.*;
import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;
import lombok.NoArgsConstructor;

@Data
@Builder
@NoArgsConstructor
@AllArgsConstructor
@Entity
@Table(name = "tokens", uniqueConstraints = {
        @UniqueConstraint(columnNames = {"user_id", "type"})
})
public class Token {
    @Id
    @GeneratedValue
    private long id;
    @Column(unique = true)
    private String token;
    @Enumerated(EnumType.STRING)
    private TokenType type;
    @ManyToOne
    @JoinColumn(name = "user_id")
    @JsonBackReference
    private User user;
}
