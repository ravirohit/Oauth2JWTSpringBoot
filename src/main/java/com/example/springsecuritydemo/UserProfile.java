package com.example.springsecuritydemo;

public class UserProfile 
{
    private String name;
    private String email;
 
    //Setters and getters
 
    
    @Override
    public String toString() {
        return "UserProfile [name=" + name + ", email=" + email + "]";
    }

	public String getName() {
		return name;
	}

	public void setName(String name) {
		this.name = name;
	}

	public String getEmail() {
		return email;
	}

	public void setEmail(String email) {
		this.email = email;
	}
}
