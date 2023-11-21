package com.security.Spring.Security.user.model;

import com.security.Spring.Security.appUser.model.AppUser;
import jakarta.persistence.*;
import lombok.AllArgsConstructor;
import lombok.Getter;
import lombok.NoArgsConstructor;
import lombok.Setter;

@Entity
@AllArgsConstructor
@NoArgsConstructor
@Setter
@Getter
public class User {
    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    private Integer id;
    @OneToOne(cascade = CascadeType.ALL, fetch = FetchType.LAZY)
    private AppUser appUser;
    @Enumerated(EnumType.STRING)
    private Gender gender;
}
