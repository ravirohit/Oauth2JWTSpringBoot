package com.example.springsecuritydemo.oauth2config;

import java.util.Arrays;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.oauth2.config.annotation.configurers.ClientDetailsServiceConfigurer;
import org.springframework.security.oauth2.config.annotation.web.configuration.AuthorizationServerConfigurerAdapter;
import org.springframework.security.oauth2.config.annotation.web.configuration.EnableAuthorizationServer;
import org.springframework.security.oauth2.config.annotation.web.configurers.AuthorizationServerEndpointsConfigurer;
import org.springframework.security.oauth2.config.annotation.web.configurers.AuthorizationServerSecurityConfigurer;
import org.springframework.security.oauth2.provider.token.TokenEnhancer;
import org.springframework.security.oauth2.provider.token.TokenEnhancerChain;
import org.springframework.security.oauth2.provider.token.TokenStore;
import org.springframework.security.oauth2.provider.token.store.JwtAccessTokenConverter;
import org.springframework.security.oauth2.provider.token.store.JwtTokenStore;

import com.example.springsecuritydemo.sscustomimpl.CustomTokenEnhancer;
 
@Configuration
@EnableAuthorizationServer
public class OAuth2AuthorizationServer extends AuthorizationServerConfigurerAdapter {
	  @Autowired
	 //@Qualifier("authenticationManagerBean")  // need to define in WebSecurityConfig.java as bean to be injected
	  private AuthenticationManager authenticationManager;
	  @Autowired
	  UserDetailsService userDetailsService;
      @Autowired
      private BCryptPasswordEncoder passwordEncoder;
 
    @Override
    public void configure(AuthorizationServerSecurityConfigurer security) throws Exception {
        security
            .tokenKeyAccess("permitAll()")
            .checkTokenAccess("isAuthenticated()")
            .allowFormAuthenticationForClients();
    }
 
    @Override
    public void configure(ClientDetailsServiceConfigurer clients) throws Exception {
        clients
            .inMemory()
            .withClient("clientapp").secret(passwordEncoder.encode("123456"))
            .authorizedGrantTypes("password", "authorization_code", "refresh_token")
            .authorities("READ_ONLY_CLIENT")
            .scopes("read_profile_info")
            .resourceIds("oauth2-resource")
            .redirectUris("http://localhost:8080/authcode")
            .accessTokenValiditySeconds(1200)
            .refreshTokenValiditySeconds(2400)
            .autoApprove(true);
    }
    @Override
    public void configure(final AuthorizationServerEndpointsConfigurer endpoints) throws Exception { 
    	// below code is for default JWT payload impl
		/*
		 * endpoints.tokenStore(tokenStore())
		 * .authenticationManager(authenticationManager)
		 * .accessTokenConverter(defaultAccessTokenConverter())
		 * .userDetailsService(userDetailsService);
		 */
    	  
    	  // below one is to implement custom payload in JWT.
    	  TokenEnhancerChain tokenEnhancerChain = new TokenEnhancerChain();
    	    tokenEnhancerChain.setTokenEnhancers(
    	      Arrays.asList(tokenEnhancer(), defaultAccessTokenConverter()));

    	    endpoints.tokenStore(tokenStore())
    	             .tokenEnhancer(tokenEnhancerChain)
    	             .authenticationManager(authenticationManager);
    }
    @Bean
    public TokenEnhancer tokenEnhancer() {
        return new CustomTokenEnhancer();
    }
    
    @Bean
    public TokenStore tokenStore(){
      return new JwtTokenStore(defaultAccessTokenConverter());
    }
    @Bean
    public JwtAccessTokenConverter defaultAccessTokenConverter() {
      JwtAccessTokenConverter converter = new JwtAccessTokenConverter();
      converter.setSigningKey("123");
      return converter;
    }
}