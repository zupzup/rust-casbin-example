# rust-casbin-example

Simple example of using [casbin-rs](https://github.com/casbin/casbin-rs) in a [warp](https://github.com/seanmonstar/warp) web service for role-based authorization.

There are three hard-coded users:

* sibylle (Admin)
* herbert (Member)
* gordon (Anonymous)

Endpoints:

* `POST /login` with the username only (`{ "name": "sibylle" }`), returns a session token
* `/logout` invalidates the session token
* `/member` only members can access this (sibylle & herbert)
* `/admin` only admins can access this (herbert)

You can run this using `make dev`, which starts a server on http://localhost:8080

```bash
curl -X POST http://localhost:8080/login -d '{ "name": "herbert" }' -H "content-type: application/json"
=> $TOKEN
curl http://localhost:8080/member -H "authorization: Bearer $TOKEN" -H "content-type: application/json"
=> 200
curl http://localhost:8080/admin -H "authorization: Bearer $TOKEN" -H "content-type: application/json"
=> 200

curl -X POST http://localhost:8080/login -d '{ "name": "sibylle" }' -H "content-type: application/json"
=> $TOKEN
curl http://localhost:8080/member -H "authorization: Bearer $TOKEN" -H "content-type: application/json"
=> 200
curl http://localhost:8080/admin -H "authorization: Bearer $TOKEN" -H "content-type: application/json"
=> 401

curl -X POST http://localhost:8080/login -d '{ "name": "gordon" }' -H "content-type: application/json"
=> $TOKEN
curl http://localhost:8080/member -H "authorization: Bearer $TOKEN" -H "content-type: application/json"
=> 401
curl http://localhost:8080/admin -H "authorization: Bearer $TOKEN" -H "content-type: application/json"
=> 401
```
