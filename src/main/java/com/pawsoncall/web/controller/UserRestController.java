package com.pawsoncall.web.controller;

import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import com.pawsoncall.web.domain.User;
import com.pawsoncall.web.mapper.UserMapper;

@RequestMapping("/users")
@RestController
public class UserRestController {

    private final UserMapper userMapper;

    public UserRestController(UserMapper userMapper) {
        this.userMapper = userMapper;
    }

    @GetMapping("{state}")
    User getUser(@PathVariable("state") String state) {
        return userMapper.findByState(state);
    }

}
