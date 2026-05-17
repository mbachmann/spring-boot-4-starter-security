package com.mbachmann.springboot4startersecurity.auth;

record AppUser(String username, String email, String passwordHash) {
}
