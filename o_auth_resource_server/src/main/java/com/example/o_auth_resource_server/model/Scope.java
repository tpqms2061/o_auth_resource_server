package com.example.o_auth_resource_server.model;

import lombok.Getter;
import lombok.RequiredArgsConstructor;

@Getter
@RequiredArgsConstructor
public enum Scope {

    READ_USERS("read:users"),
    WRITE_USERS("write:users"),
    READ_POSTS("read:posts"),
    WRITE_POSTS("write:posts"),
    ADMIN("admin");

    private final String value;
}
