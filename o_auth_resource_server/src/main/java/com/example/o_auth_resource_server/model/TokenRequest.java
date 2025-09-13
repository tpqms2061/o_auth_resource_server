package com.example.o_auth_resource_server.model;


import lombok.AllArgsConstructor;
import lombok.Getter;
import lombok.Setter;

@Getter
@Setter
@AllArgsConstructor
public class TokenRequest {
    private String username;
    private String password;
    private String scope;

}
