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
@Table(name = "tokens")
public class Token {
    @Id
    @GeneratedValue
    private long id;
    @Column(unique = true)
    private String token;
    @OneToOne
    @JoinColumn(name = "user_id",unique = true)
    @JsonBackReference
    private User user;
}
