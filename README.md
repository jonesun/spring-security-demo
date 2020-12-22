oauth2-server	8080	授权服务器
oauth2-resource	8880	资源服务器

```

###

# curl -X POST --user 'clientapp:123' -d 'grant_type=password&username=user&password=123456' http://localhost:8080/oauth/token
POST http://localhost:8080/oauth/token
Authorization: Basic clientapp 123
Content-Type: application/x-www-form-urlencoded

grant_type=password&username=user&password=123456

###
# curl -X POST -H "authorization: Bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJleHAiOjE1NTQ0MzExMDgsInVzZXJfbmFtZSI6InVzZXIiLCJhdXRob3JpdGllcyI6WyJST0xFX1VTRVIiXSwianRpIjoiOGM0YWMyOTYtMDQwYS00Y2UzLTg5MTAtMWJmNjZkYTQwOTk3IiwiY2xpZW50X2lkIjoiY2xpZW50YXBwIiwic2NvcGUiOlsicmVhZCJdfQ.YAaSRN0iftmlR6Khz9UxNNEpHHn8zhZwlQrCUCPUmsU" -d 'name=zhangsan' http://localhost:8081/api/hi
POST http://localhost:8880/api/hi
authorization: Bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJleHAiOjE2MDg2NzI4NzIsInVzZXJfbmFtZSI6InVzZXIiLCJhdXRob3JpdGllcyI6WyJST0xFX1VTRVIiXSwianRpIjoicEcyWURaUUVwa3JPT2E4WTc3OHRfOTgtS053IiwiY2xpZW50X2lkIjoiY2xpZW50YXBwIiwic2NvcGUiOlsicmVhZCJdfQ.ZardDYRaBjHHpExUB3VcfTRJV2Y6YU6mG09JA_x3-AA
Content-Type: application/x-www-form-urlencoded

name=zhangsan

```