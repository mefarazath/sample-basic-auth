# Custom Basic Authenticator Samples

1. mvn clean install
2. Copy components/org.wso2.carbon.identity.application.authenticator.basicauth.custom/target/org.wso2.carbon.identity.application.authenticator.basicauth.custom-6.0.9-SNAPSHOT.jar to IS_HOME/repository/components/dropins
3. Copy resources/login.jsp IS_HOME/repository/deployment/server/webapps/authenticationendpoint/


Configuring
* Custom Basic Request Path Authenticator
![Alt text](resources/basic-requestpath.png?raw=true "Custom Basic Authenticator")



* Custom Basic Authenticator
![Alt text](resources/basic-auth.png?raw=true "Custom Basic Request Path Authenticator")



Sample Requests
1. Custom Basic Request Path Authenticator (Credentials sent in the Basic Auth header in request)

` curl -k -v  --user admin:admin  https://localhost:9443/oauth2/authorize?response_type=code&client_id=H4nlWzP11x_DwtgavojIAW5sYnUa&redirect_uri=https://localhost/callback&scope=openid
`

2. Custom Basic Authenticator 

`https://localhost:9443/oauth2/authorize?response_type=code&client_id=11FIYleecll80kNUB3ENnjJ26dMa&redirect_uri=https://localhost/callback&scope=openid`
