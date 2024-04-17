package com.shubham.blog.service;


import java.util.List;

import com.shubham.blog.payloads.UserDto;

public interface UserService {

	UserDto registerNewUser(UserDto user);
	UserDto createUser(UserDto userDto);
	UserDto updateUser(UserDto userDto, Integer userId);
	UserDto getUserById(Integer userId);
	List<UserDto> getAllUser();
	
	void deleteUser(Integer userId);
}
