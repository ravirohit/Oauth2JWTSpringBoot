package com.example.springsecuritydemo;

import java.security.Principal;

import org.springframework.http.ResponseEntity;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.RestController;

import com.example.springsecuritydemo.sscustomimpl.CustomUser;
 
@RestController
public class RestResource 
{
    @GetMapping("/api/users/me")
    public ResponseEntity<UserProfile> profile() 
    {
        //Build some dummy data to return for testing
    	//CustomUser user = (CustomUser) SecurityContextHolder.getContext().getAuthentication().getPrincipal();
    	System.out.println("profile() method get invoked:"+SecurityContextHolder.getContext().getAuthentication().getPrincipal());
        String email = "ravi" + "@howtodoinjava.com";
 
        UserProfile profile = new UserProfile();
        profile.setName("ravi");
        profile.setEmail(email);
 
        return ResponseEntity.ok(profile);
    }
    @GetMapping("/api/users/me1")
    public ResponseEntity<Principal> get(final Principal principal) {
        return ResponseEntity.ok(principal);
    }
    @GetMapping("/authcode")
    public void authCode(@RequestParam(required = false) String code){
    	System.out.println("received code is:"+code);
    	
    }
}
