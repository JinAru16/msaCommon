package com.msa.common;

import com.msa.common.entity.Role;
import com.msa.common.entity.Users;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.userdetails.UserDetails;

import java.util.Collection;
import java.util.List;
import java.util.Map;

public class UserDetailsImpl implements UserDetails {
    private  Long id;
    private final String username;
    private final String password;
    private final String email;
    private final String nickname;
    private final Role role;
    private  Map<String, Object> attributes;

    // 일반 로그인용
    public UserDetailsImpl(Users usersByUsername) {
            this.id = usersByUsername.getId();
            this.username = usersByUsername.getUsername();
            this.password = usersByUsername.getPassword();
            this.email = usersByUsername.getEmail();
            this.nickname = usersByUsername.getNickname();
            this.role = usersByUsername.getRole();
    }

    @Override
    public Collection<? extends GrantedAuthority> getAuthorities() {
        return List.of(new SimpleGrantedAuthority("ROLE_" + this.role));
    }

    @Override
    public String getPassword() {
        return this.password;
    }

    @Override
    public String getUsername() {
        return this.username;
    }

    public String getRole(){
        return this.role.toString();
    }

}
