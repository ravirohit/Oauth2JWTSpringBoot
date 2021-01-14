Ref link: 
  https://howtodoinjava.com/spring-boot2/oauth2-auth-server/
  https://dzone.com/articles/secure-spring-rest-api-using-oauth2-1
  https://stackoverflow.com/questions/46862840/unable-to-use-resourceserverconfigureradapter-and-websecurityconfigureradapter-i
customUserDetailsService impl ref link:
  http://progressivecoder.com/implementing-spring-boot-security-using-userdetailsservice/
-> Implementation to add custom token in Jwt token:
  https://www.baeldung.com/spring-security-oauth-jwt-legacy
-> Ref to skip Oauth user approval page to direct from login page to client redirect url with Auth Code.
  https://stackoverflow.com/questions/29696004/skip-oauth-user-approval-in-spring-boot-oauth2

----------------------
-> project name: spring-security-demo
-> Run as java application from file containing main class: SpringSecurityDemoApplication.java
-> Steps to get auth code:
   -> open chrome browser and enter below url:
      http://localhost:8080/oauth/authorize?client_id=clientapp&response_type=code&scope=read_profile_info
   -> it will redirect to login page, enter below credential which is defined in WebSecurityConfig.java
      username: humptydumpty
      password: 123456
             OR 
      try the same username and password. it should work as i have customized it in CustomUserDetailsService.java
   -> it will redirect to a page http://localhost:8081/login passing the auth code as query param to the same redirect url.
      it is defined in OAuth2AuthorizationServer.java file.

-> use Auth code to get access token from authorization server. I am using Postman for this purpose:
   -> Lunch postman 
   -> select POST Http method type.
   -> enter url: http://localhost:8080/oauth/token
   -> add header: 
      Authorization: Basic ${cliendId:secret}           // defined in OAuth2AuthorizationServer.java
       Ex: 
        base64 of "clientapp:123456" is: Y2xpZW50YXBwOjEyMzQ1Ng==
        Authorization: Basic Y2xpZW50YXBwOjEyMzQ1Ng==
      Content-Type: application/x-www-form-urlencoded
   -> under body, select x-www-form-urlencoded radio button and provide below key value pair information:
      key: grant_type     value: authorization_code
      key: code           value: y94hTO
      key: redirect_uri   value: http://localhost:8081/login
   -> once you will hit the api, response will be:
       {
		    "access_token": "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJhdWQiOlsib2F1dGgyLXJlc291cmNlIl0sInVzZXJfbmFtZSI6InJhdiIsInNjb3BlIjpbInJlYWRfcHJvZmlsZV9pbmZvIl0sImV4cCI6MTYxMDYxMjAyMCwiYXV0aG9yaXRpZXMiOlsiVVNFUiJdLCJqdGkiOiI1N2M2NzI5YS0xYjUwLTQyM2UtYWUzYi0yNGMxNjNiNDY4ZTIiLCJjbGllbnRfaWQiOiJjbGllbnRhcHAifQ.TtWQJwh7zpTencq4SJvVC_uJxcURt_WCAOFinaAG-H8",
		    "token_type": "bearer",
		    "refresh_token": "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJhdWQiOlsib2F1dGgyLXJlc291cmNlIl0sInVzZXJfbmFtZSI6InJhdiIsInNjb3BlIjpbInJlYWRfcHJvZmlsZV9pbmZvIl0sImF0aSI6IjU3YzY3MjlhLTFiNTAtNDIzZS1hZTNiLTI0YzE2M2I0NjhlMiIsImV4cCI6MTYxMDYxMzIyMCwiYXV0aG9yaXRpZXMiOlsiVVNFUiJdLCJqdGkiOiI1YmY2ODczYy05MGJhLTRmMDgtODRjMy04ZDhjM2Y0MjVjODEiLCJjbGllbnRfaWQiOiJjbGllbnRhcHAifQ.NZSt2jp_yIiXyd5Y_oU4bpEA9rzgDcOLKiUqJUku_OU",
		    "expires_in": 1199,
		    "scope": "read_profile_info",
		    "jti": "57c6729a-1b50-423e-ae3b-24c163b468e2"
		}
 -> Use access_token to invoke resource api:
    -> select method type: GET
    -> enter url: http://localhost:8080/api/users/me
    -> add Header:
       Authorization: Bearer ${access_token_value}
    -> hit the Url, response will be:
        {
		    "name": "humptydumpty",
		    "email": "humptydumpty@howtodoinjava.com"
		}
   
=== ERROR ============
ERROR:
  o.s.s.c.bcrypt.BCryptPasswordEncoder     : Encoded password does not look like BCrypt
Solution:
  There is two places where user credential is used.
  1. when we are retrieving the user data from db and storing it in CustomUser class object. 
     this operation is happening in CustomUserDetailsService.java class.
  2. There is another place where we provide CustomUserDetailsService class object and PasswordEncoder object where 
     Spring boot would be reading user info from CustomUser object.
     this object is provided to spring boot in WebSecurityConfig.java file.
     NOTE: When Spring boot read password from CustomUser object. which has been initialized. it assume we have encoded the
     password first then initialize it. and when spring read the password, first it decode it before using.
  As i was not encoding the password before storing it in CustomUser object. and Spring was using the passowrd after 
  decoding, it was causing "Bad Credential" error in UI side and in backend error is "Encoded password does not look like BCrypt"
  Solution:
    I have added below code to encode the password before initialize it in CustomUserDetailsService.java:
    
    customUser.setPassword(passwordEncoder().encode(username));  and  // username is password string
    
    public PasswordEncoder passwordEncoder() {
      return new BCryptPasswordEncoder();
    }
    
===================== NOTE =============================
-> That we used a symmetric key in our JwtAccessTokenConverter to sign our tokens – which means we will need to use the 
   same exact key for the Resources Server as well.

   
   
   
   
   
   
   
   
   
   
   