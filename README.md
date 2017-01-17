# JWT_SSO
Java8, gradle, spring boot 1.4.0.RELEASE, freemarker

## RESOURCE SERVICE
Service is protected resource:
http://localhost:9000/protected-resource

After accessing it you are redirected to 
http://localhost:8080/login?redirect=http://localhost:9000/protected-resource

## AUTHORIZATION SERVICE
http://localhost:8080
This is authorization service, where you enter your creds (in memory admin/admin or user/password)
Service generates JWT token with claim data (username, issuedDate, expirationDate (expirationDate = issuedDate + 1min, the token time to live is controlled by a property  services.expiration.min = 1), serviceName, userRoleForService), stores it in cookie (services.cookieName=JWT-TOKEN) and adds signature to it using HS256. So the JWT token is valid for all another services within 1 min (small value just for testing).
Signature is stored in properties file: services.signinKey=signingKey

## NOTES
Use https://jwt.io to decoded data in token.
You can start one more resource service using profile with paramether:

java -jar resourceService-0.0.1-SNAPSHOT.jar -Dspring.profiles.active=9091

or just overriding the port number:

java -jar resourceService-0.0.1-SNAPSHOT.jar -Dserver.port=9001

java -jar resourceService-0.0.1-SNAPSHOT.jar -Dserver.port=9002

## TODO ITEMS

- [x] Created auth and resource services
- [ ] Add docker virtualization
- [ ] Add MockMvc tests
