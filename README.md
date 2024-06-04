# PawsOnCall-Web
the Web Project of PawsOnCall

# How to run
```bash
./mvnw spring-boot:run
# open another terminal, expect {"id":1,"name":"Foo","state":"CA","country":"US"}
curl -X GET "http://localhost:18080/users/CA"
```