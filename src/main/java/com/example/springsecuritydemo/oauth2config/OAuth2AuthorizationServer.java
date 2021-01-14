package com.example.springsecuritydemo.oauth2config;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Qualifier;
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
import org.springframework.security.oauth2.provider.token.TokenStore;
import org.springframework.security.oauth2.provider.token.store.JwtAccessTokenConverter;
import org.springframework.security.oauth2.provider.token.store.JwtTokenStore;
 
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
            .refreshTokenValiditySeconds(2400);
    }
    @Override
    public void configure(final AuthorizationServerEndpointsConfigurer endpoints) throws Exception { 
    	  endpoints.tokenStore(tokenStore()).authenticationManager(authenticationManager).accessTokenConverter(defaultAccessTokenConverter())
         .userDetailsService(userDetailsService);
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