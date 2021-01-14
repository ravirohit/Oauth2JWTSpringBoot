package com.example.springsecuritydemo.sscustomimpl;

import java.util.ArrayList;
import java.util.List;

import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;


// https://www.baeldung.com/spring-security-authentication-with-a-database
@Service
public class CustomUserDetailsService implements UserDetailsService {
 
	/*
	 * @Autowired private UserDaoRepository userDaoRepository;
	 */
	
    @Override
    public CustomUser loadUserByUsername(String username) throws UsernameNotFoundException {
    	 //Write your DB call code to get the user details from DB,But I am just hard coding the user
    	System.out.println("************ load User by username called for username:"+username+" **********");
    	// if NOT FOUND in db through exception UsernameNotFoundException
    	CustomUser customUser = new CustomUser();
    	customUser.setUsername(username);
    	customUser.setPassword(passwordEncoder().encode(username));
    	Role role= new Role();
    	role.setRole("USER");
    	List<Role> roleList = new ArrayList<>();
    	roleList.add(role);
    	customUser.setAuthorities(roleList);
       // return userDaoRepository.getUser(username);
    	return customUser;
    }
    public PasswordEncoder passwordEncoder() {
      return new BCryptPasswordEncoder();
    }
 
}
