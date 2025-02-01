package com.security.securitydemo.jwt;

public class LoginRequest {
    private String username;
    private String password;

    public String getUsername() {
        return username;
    }

    private void setUsername (String username) {
        this.username = username;
    }

    public String getPassword () {
        return password;
    }

    private void setPassword(String password) {
        this.password = password;
    }
}
