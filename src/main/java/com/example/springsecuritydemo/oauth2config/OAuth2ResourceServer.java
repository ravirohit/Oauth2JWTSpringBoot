package com.example.springsecuritydemo.oauth2config;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.oauth2.config.annotation.web.configuration.EnableResourceServer;
import org.springframework.security.oauth2.config.annotation.web.configuration.ResourceServerConfigurerAdapter;
import org.springframework.security.oauth2.config.annotation.web.configurers.ResourceServerSecurityConfigurer;
import org.springframework.security.oauth2.provider.token.TokenStore;

@Configuration
@EnableResourceServer
public class OAuth2ResourceServer extends ResourceServerConfigurerAdapter {

	/*
	 * @Override public void configure(ResourceServerSecurityConfigurer resources) {
	 * resources .resourceId(RESOURCE_ID) .tokenStore(tokenStore); }
	 */
	
	
	@Override
	public void configure(HttpSecurity http) throws Exception {
		
		/*
		 * http.authorizeRequests().antMatchers("/api/**").authenticated().antMatchers(
		 * "/").permitAll();
		 */
		 
		http.antMatcher("/api/**").authorizeRequests().anyRequest().authenticated();
	}
	
}

