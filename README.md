# auth-demo

## Introduction

These are the results of a coding exercise to update my knowledge about AWS, Docker, Javascript, shell scripting, JWTs, and REST authentication.

Many of the concepts embodied here have their beginnings in a session-based authentication manager I developed for a high performance 
relationsal transaction processing system 3-4 years ago.  That system needed some method of establishing user identity, usually by verifying 
a username password against a Microsoft Active Directory service.  It also needed a concept of perimeter security, that prevented unauthorized 
users from accessing the system via REST APIs.  The initial implementation I created used a hexadecimal session token whose contents were verified
by a Javascript (later Typescript) middleware service that acted as a service proxy for HTTP, gRPC, and WebSocket traffic.  That session token 
implementation was later modified to use a JSON Web Token (JWT) because the Caddy web server that provided access to the system was capable of
accepting or rejecting connecitons based on the presence of a JWT cookie attached to the HTTP request.

Many things have changed in the technologies used to create that stack in the time since it was developed.  Much of Javascript development 
has more fully migrated to Typescript. Nodejs has released several major versions, as have large numbers of node packages.  Docker Compose 
has been re-implemented as a docker plugin. Redhat was acquired by IBM; CentOS has gone from a public build of proprietary RedHat to a 
feature qualification step between Fedora and RedHat Enterprise Linux. Go has preliforated, and the Caddy web server (written in Go) has 
become a more known competitor to Nginx.

## Design Considerations

After 2-3 years away from developing with these tools, it seemed a good time brush up old skills and see what, if any, improvements had been
made.  The first phase of the demonstration would consist of three tiers:

1. A web tier -- For the sake of simplicity, this would be hosted using the Caddy web server.  Caddy is deployed as a single static binary file
with a JSON configuration file.  That makes it easy to deploy in simple stacks like this, but still remains an extensible web server with a 
a significant suite of features.  The function of the web tier would be two fold: to define top-level REST interface points and then to 
provide security for those points.  Server level security would examine some kind of session token and determine access based on the contents.

2. An authentication tier -- This would be a Javascript microservice running in a recent version of NodeJS.  To simplify development, it would
use the Express framework for specifying the REST interface, and the Passport framework for handling authentication.  The goal would to be 
to support two authentication back ends: one that would be service-based (like Active Directory or LDAP) and one that would be file-based. 
The motivating idea is that a useful authentication deployment has two different kinds accounts.  There are a small number of administrative 
accounts that need to accessible (from a file) when the system a user identity service is down.  There is a much larger and more scalable 
number of accounts available from a proper user management service for regular use.

3. An identity tier -- This would most directly consist of an OpenLDAP instance used as an authentication back end.  There also needs to be a
password file somewhere; it is logically co-located with the authentication service since it is just a passive file.

There are a few additional design details to consider.  The Express framework requires its own backend to store session data.  Though a 
local file-based session store is the simplest choice, it is not necessarily the most performant because it requires a file system access to
retrieve session information every time.  An active service capable of holding (or caching) session data in memory is likely to be a more
performant option.

There is also the problem of what password file format to use.  A variety of password file formats exist.  There is no point in creating a 
new one.  A format that is fully encrypted while the file sits "at rest" would be advantageous; `/etc/passwd` style files give away too much
account infomration, for example.  Since there is some commitment to using the Passport framework for authentication, there is also the question
of what file formats it supports via its plugin mechanism (plugins are called "Strategies".)  

Finally, there is the question of how to configure Caddy to handle the session security.  The authentication tier provides some kind of session 
information at can be attached to subsequent requests.  It needs to be provided in a way that both the web tier and authentication tier both 
understand. 


## Implementation Choices

The first deployment platform for the stack is "docker" and "docker compose."  RedHat now provides a significant list of RHEL containers, 
including that have stacks like Nodejs pre-built.  The stack is developed a workstation running Ubuntu 18.  This rules out using the latest 
RHEL 9 docker containers because the kernel ABIs are incompatible.  RHEL 8 containers were used instead.

The initial REST interface is just boiled down to three essential calls:

```
/auth

/reader

/writer
```

The `/auth` access point is how clients communicate with the authentication tier.  Username and password are provided in a POST request.
Successful authentication returns `200 - OK` with a session cookie attached.  That cookie is then saved in a cookie jar and presented with
subsequent interaction with the `/reader` and `/writer` interfaces.  The cookie contains role-based session information that Caddy can use
to allow or deny access to those interfaces.

That session cookie is a JWT.  This was done for two reasons.  First, the necessary session middleware exists.  The Express framework
has tried and tested middleware extenstion called `express-session`.  That extension generally provides as a hexadecimal string that acts
as a hash key to retrieve session information.  That's unsuitable for the OAuth-like semantics implemented at the Caddy tier her.  Instead,
a package called `express-session-jwt` exists.  This is a drop in replacement for `express-session` that returns a JWT as the session
cookie.  Since a JWT has a Roles field in its payload, these are used to determine if access to a particular REST interface is appropriate.

The second reason is that Caddy can do access security using JWTs.  At least two caddy plugins support JWT access: 
the [`caddy-security`](https://github.com/greenpau/caddy-security) plugin by Paul Greenberg and 
the [`caddy-jwt`](https://github.com/ggicci/caddy-jwt) plugin written by Ggicci.  Choosing between them took longer than it should have.
The `caddy-security` plugin is obviously the bigger, more fully featured plugin with a full web site devoted to its features.  The 
problem with that web site was that it presents a lot of facts, but does not spend much time discussing the application of those facts 
to particular use cases, at first. Those questions about use case were all eventually answered by the video 
[Caddy Authorize: Authorizing HTTP Requests](https://www.youtube.com/watch?v=Mxbjfv47YiQ&t=1s&vq=hd1080) that is present as a link on the
`caddy-security` Introduction page.  Without the information in that video, `caddy-jwt` seemed a viable alternative.  It employs a
Caddy middleware layer that is documented by the Caddy web site but again with few useful examples showing how all the pieces fit together.
Thankfully, the `caddy-security` videos fill in a lot of gaps that made writing authorization rules in a Caddyfile a job only requiring
a couple hours, start to finish.

Using a JWT does add a small amount of complexity to the implementation.  The JWTs generated by the authentication layer are signed with
a `ECDSA + P-256` public/private key pair.  The `caddy-security` layer is capable of verifying the signature, if it has access to 
the public key.  The key could be passed into both as an environment variable, but encryption keys are better passed as files.  Each
layer is a separate Docker container built from a separate directory with a separate Dockerfile.  Sharing the key files means that the 
problem of sharing files across Docker builds needs to be resolved.

Getting a useful LDAP Docker container was also an implementation problem.  OpenLDAP can be installed in a plain RedHat container.  The 
problem there is that it needs to be configured: with an administrator (and password,) a basic schema, and schema customizations. 
OpenLDAP is also available from a pre-configured Docker container by [https://hub.docker.com/r/bitnami/openldap/](Bitnami). That comes
pre-configured except for some environment variables that set most of the constomizations needed.  Most does not mean all however. 
Additional data reprsenting the `reader` and `writer` roles needed to be automatically populated into the container when it started to 
automate deployment.  Writing a lot of LDIF to completely configure an OpenLDAP instance felt like future work, and the Bitnami conainer 
was used.  Automating deployment became a problem of introducing some additional startup scripts into the Bitnami container to add the 
needed data, and then appending calls to those scripts the shell script Bitnami uses to configure LDAP during the first startup of the 
container.

Choosing a password file format that worked with Passport proved to be another major hurdle for the project.  The Passport framework 
works with primarily with authentication services, not file formats.  There are multiple OAuth impelementations, at least one SAML 
implementation, and several service SSO implementations.  Files are deemed too simple in some ways.  Fortunately, there was a prototype 
for a Buttercup password vault strategy implementation written 4 years ago along with the rest of the auth implementation that originally 
inspired this project.  It was never used in any commercial product, and  was completely re-written as a part of this effort.  Is is now
available on [npmjs](https://www.npmjs.com/package/passport-buttercup).

The last piece of the implementation puzzle was to choose a back end for the Express framework.  While initial testing just wrote session 
data to a directory tree in the `/tmp` filesystem, `memcached` was eventually picked as the back end.  It's older, proven technology that 
is easily installed on RedHat in the same docker container as the NodeJS running the authentication microservice.  The only problem this 
introduced was the problem of running more than one microservice in a Docker container.  `supervisord` was used to manage both processes.

## Configuration

This section discusses environment variables used to configure this implementation.  This will be 
done a per-topic basis where a particular aspect of operation is first discussed and then the 
relevant configuration variables are listed.

Authentication for this demo works in two phases.  First, it ensures that the username and password
match those stored either in the OpenLDAP directory or the Buttercup vault file.  The LDAP 
authentication is accomplished using a special LDAP user (that can have read only privileges) that
searches speific directory locations for user records. For Buttercup, it 
involves opening the vault file using the master password and then matching the username and 
password values against the decrypted plaintext of the corresponding fields in the file. 
Second, the Passport strategy configurations look at the list of LDAP groups to which users belong 
or which named properties each mactching user has.  A "writer" group or property corresponds 
to the `authp/writer` role; a "reader" group or property corresponds to `authp/reader`. 
The two roles correspond to the ability to access the `/writer` and `/reader` REST access points, 
respectively.

Buttercup file vaults have the ability to cluster user credentials into different categories called 
Groups.  It's much like creating different LDAP Distinguished Names to create different directories
of usernames.  The `passport-buttercup` strategy has the ability to specify which Group a potential 
authentication match belongs to.  If the Group name matches, the username/password is accepted; if not,
it is rejected.  This allows non-unique usernames to be used with (potentially) different passwords to 
authenticate for different purposes.

Since the LDAP directory is dynamically created during the first startup of the docker container, 
much of the setup can be controlled with values in the `docker-compose.yml` file. The format of
the contents of the Buttercup vault file is already set when the filename is supplied to the docker 
container as it is built.

```
AUTH_USER FIELD (default: xiusername)
This controls the field name for the account username used in the POST request to get a session JWT.
AUTH_PASSWORD_FIELD (default: xipassword)
This controls the field name for the account password used in the POST request to get a session JWT.
AUTH_LDAP_READER_GROUP (default: db_readers)
The name of the LDAP group that controls access to the /readers REST interface.
AUTH_LDAP_WRITER_GROUP (default: db_writers)
The name of the LDAP group that controls access to the /writers REST interface.
AUTH_LDAP_DB_WRITERS (default: the Bitnami list of LDAP_USERS)
The list of LDAP users that belong to the AUTH_LDAP_WRITER_GROUP
AUTH_LDAP_DB_READERS (default: the Bitnami list of LDAP_USERS)
The list of LDAP users that belong to the AUTH_LDAP_READER_GROUP
AUTH_BCUP_DBREADER_NAME (default: db_reader)
The name of the Buttercup user property that corresponds to access to the /readers REST interface
AUTH_BCUP_DBWRITER_NAME (defaut: db_writer)
The name of the Buttercup user property that corresponds to access to the /writers REST interface
AUTH_BCUP_MASTER_PASSWORD (no default)
The Buttercup master password used to decrypt the vault file
AUTH_BCUP_FILE_NAME (default: /opt/app-root/src/authPassword.bcup)
The path to the Buttercup vault file inside the auth-server Docker container.
AUTH_BCUP_GROUP_NAME (default: General)
The Group name where matching passwords can be found
```

Several environment variables are used to specify names or locations of files within Docker 
containers.  These are:

```
AUTH_BCUP_FILE_NAME (default: /opt/app-root/src/authPassword.bcup)
The path to the Buttercup vault file inside the auth-server Docker container.
AUTH_CONFIG_PATH (default: /opt/app-root/src/dockerConfig.json)
The path to the passport-ldapauth Passport Strategy config file (see below)
AUTH_PUBLIC_KEY (default: /opt/app-root/src/public-key.pem)
The path to the public key used to validate JWTs in the auth-server
AUTH_PRIVATE_KEY (default: /opt/app-root/src/private-key.pem)
The path to the private key used to sign JWTs in the auth-server
JWT_SHARED_KEY (default: /www/public-key.pem)
The path to the public key used to validate JWTs in Caddy
AUTH_FILE_STORE_PATH (default: /tmp/session)
The path used by the Express framework when it uses a backing File Store (see dataStoreType below) in the auth-server
```
In addition to environment variables, the `passport-ldapauth` Passport Strategy is configured 
using a JSON file (see `AUTH_CONFIG_PATH` above.)  The values in this file are:

```
url 
The ldap URI for the OpenLDAP server in the identity tier.
bindDN 
The DN identity of the user that scans the searchBase and groupSearchBase of the OpenLDAP instance.
bindCredentials 
The password for the bindDN user (see above).
searchBase 
The DN used to search for user records.
searchFilter 
The filter used to find matching user records during authentication.
searchScope
The type of LDAP search (base, one sub) used to find user entries
searchAttributes (default: undefined)
When returning user records, filter the records returned based this array of attribute names; undefined fetches all
groupSearchBase 
The DN used to search for groups to which users belong.
groupSearchScope 
The type of LDAP search (base, one, sub) to find user membership in groups
groupSearchFilter 
The filter used to find how users are members of groups.
TLSOpts 
Options used by the NodeJS tls module to identify and validate security keys if the LDAPS protocol is used
dbReaderGroup 
The name of the LDAP group to which users with the authp/readers role belong see: AUTH_LDAP_READER_GROUP
dbWriterGroup 
The name of the LDAP group to which users with the authp/writers role belong see: AUTH_LDAP_WRITER_GROUP
```
There are also a number of miscellaneous environment variables that impact the configuration by impacting service types and addresses:

```
AUTH_SESSION_STORE_TYPE (default: memcacheStore)
The type of Express session backing store type (values: memcacheStore, fileStore)
AUTH_MEMCACHE_HOST (default 127.0.0.1)
The hostname/ip address of the memcached instance to be used as the auth-server Express session backing store
AUTH_MEMCACHE_PORT (default: 11211)
The tcp port of the memcached instance to be used as the auth-server Express session backing store
AUTH_SERVER_PROXY_HOST (default: auth-server)
The hostname/ip address of the auth-server instance used for authentication
AUTH_SERVER_PROXY_PORT (default: 12123)
The tcp port of the auth-server instance used for authentication
```

Additional environment variables can be found in the documentation for the [Bitnami LDAP docker container](https://hub.docker.com/r/bitnami/openldap/).
Additional information about JSON configuration can be found in the documentation for [passport-ldapauth](https://www.npmjs.com/package/passport-ldapauth), [passport-ldapauth-fork](https://www.npmjs.com/package/passport-ldapauth-fork), and [NodeJS tls](https://nodejs.org/api/tls.html#tls_tls_connect_options_callback).

## Operation

Building the stack is straightforward, but could not be reduced to a single step.  Keys to sign and verify the JWTs need to be found in the 
`/common` subdirectory and named `public-key.pem` and `private-key.pem`.  These are copied into the Docker containers.  The `Makefile` 
in the `/common` directory uses `openssl` to generate a pair of keys if others are not available.  The full steps to build the stack the
first time are:

```
cd common
make
cd ..
docker compose build
```

Starting the cluster is a single command:

```
docker compose up
```

This is how it looks to startup:

```docker compose up
[+] Running 6/6
 ⠿ Network auth-demo_midtier           Created                                                                                       0.0s
 ⠿ Network auth-demo_default           Created                                                                                       0.1s
 ⠿ Network auth-demo_backend           Created                                                                                       0.0s
 ⠿ Container auth-demo-ldap-server-1   Created                                                                                       0.2s
 ⠿ Container auth-demo-auth-server-1   Created                                                                                       0.2s
 ⠿ Container auth-demo-caddy-server-1  Created                                                                                       0.2s
Attaching to auth-demo-auth-server-1, auth-demo-caddy-server-1, auth-demo-ldap-server-1
auth-demo-auth-server-1   | 2023-03-15 22:16:36,873 INFO Included extra file "/etc/supervisord.d/auth-server.ini" during parsing
auth-demo-auth-server-1   | 2023-03-15 22:16:36,875 INFO RPC interface 'supervisor' initialized
auth-demo-auth-server-1   | 2023-03-15 22:16:36,875 CRIT Server 'unix_http_server' running without any HTTP authentication checking
auth-demo-auth-server-1   | 2023-03-15 22:16:36,875 INFO supervisord started with pid 1
auth-demo-ldap-server-1   |  22:16:37.64 INFO  ==> ** Starting LDAP setup **
auth-demo-ldap-server-1   |  22:16:37.67 INFO  ==> Validating settings in LDAP_* env vars
auth-demo-ldap-server-1   |  22:16:37.67 INFO  ==> Initializing OpenLDAP...
auth-demo-ldap-server-1   |  22:16:37.68 INFO  ==> Creating LDAP online configuration
auth-demo-ldap-server-1   |  22:16:37.68 INFO  ==> Creating slapd.ldif
auth-demo-ldap-server-1   |  22:16:37.70 INFO  ==> Starting OpenLDAP server in background
auth-demo-auth-server-1   | 2023-03-15 22:16:37,880 INFO spawned: 'auth-server' with pid 8
auth-demo-auth-server-1   | 2023-03-15 22:16:37,884 INFO spawned: 'memcache' with pid 9
auth-demo-ldap-server-1   |  22:16:38.71 INFO  ==> Configure LDAP credentials for admin user
auth-demo-ldap-server-1   |  22:16:38.71 INFO  ==> Adding LDAP extra schemas
auth-demo-ldap-server-1   |  22:16:38.73 INFO  ==> Creating LDAP default tree
auth-demo-caddy-server-1  | {"level":"info","ts":1678918599.0740921,"msg":"using provided configuration","config_file":"/etc/caddy/Caddyfile","config_adapter":""}
auth-demo-caddy-server-1  | {"level":"warn","ts":1678918599.0752199,"msg":"Caddyfile input is not formatted; run the 'caddy fmt' command to fix inconsistencies","adapter":"caddyfile","file":"/etc/caddy/Caddyfile","line":2}
auth-demo-caddy-server-1  | {"level":"info","ts":1678918599.0757978,"logger":"admin","msg":"admin endpoint started","address":"localhost:2019","enforce_origin":false,"origins":["//localhost:2019","//[::1]:2019","//127.0.0.1:2019"]}
auth-demo-caddy-server-1  | {"level":"warn","ts":1678918599.075878,"logger":"http","msg":"server is listening only on the HTTP port, so no automatic HTTPS will be applied to this server","server_name":"srv0","http_port":8080}
auth-demo-caddy-server-1  | {"level":"info","ts":1678918599.0759604,"logger":"tls.cache.maintenance","msg":"started background certificate maintenance","cache":"0xc00037f340"}
auth-demo-caddy-server-1  | {"level":"info","ts":1678918599.076045,"logger":"security","msg":"provisioning app instance","app":"security"}
auth-demo-caddy-server-1  | {"level":"info","ts":1678918599.076177,"logger":"security","msg":"provisioned app instance","app":"security"}
auth-demo-caddy-server-1  | {"level":"info","ts":1678918599.0763466,"logger":"http.log","msg":"server running","name":"srv0","protocols":["h1","h2","h3"]}
auth-demo-caddy-server-1  | {"level":"info","ts":1678918599.076379,"logger":"tls","msg":"cleaning storage unit","description":"FileStorage:/home/caddy-owner/.local/share/caddy"}
auth-demo-caddy-server-1  | {"level":"info","ts":1678918599.0764177,"logger":"tls","msg":"finished cleaning storage units"}
auth-demo-caddy-server-1  | {"level":"info","ts":1678918599.0764663,"msg":"autosaved config (load with --resume flag)","file":"/home/caddy-owner/.config/caddy/autosave.json"}
auth-demo-caddy-server-1  | {"level":"info","ts":1678918599.076473,"msg":"serving initial configuration"}
auth-demo-auth-server-1   | 2023-03-15 22:16:39,636 INFO success: auth-server entered RUNNING state, process has stayed up for > than 1 seconds (startsecs)
auth-demo-auth-server-1   | 2023-03-15 22:16:39,636 INFO success: memcache entered RUNNING state, process has stayed up for > than 1 seconds (startsecs)
auth-demo-ldap-server-1   |  22:16:39.87 INFO  ==> Validating settings in AUTH_LDAP_* env vars
auth-demo-ldap-server-1   |  22:16:39.88 INFO  ==> Starting stage2 initialize
auth-demo-ldap-server-1   |  22:16:39.89 INFO  ==> Starting OpenLDAP server in background
auth-demo-ldap-server-1   |  22:16:41.99 INFO  ==> ** LDAP setup finished! **
auth-demo-ldap-server-1   | 
auth-demo-ldap-server-1   |  22:16:42.04 INFO  ==> ** Starting slapd **
auth-demo-ldap-server-1   | 641243ca.03142637 0x7f310d817740 @(#) $OpenLDAP: slapd 2.6.4 (Feb 22 2023 11:46:45) $
auth-demo-ldap-server-1   | 	@e337c9d3914b:/bitnami/blacksmith-sandox/openldap-2.6.4/servers/slapd
auth-demo-ldap-server-1   | 641243ca.03d6c7c5 0x7f310d817740 slapd starting
```

The following part of the Caddyfile implements the HTTP interface:

```
*:8080 {
    route /auth {
        reverse_proxy {env.AUTH_SERVER_PROXY_ADDRESS}
    }

    route /reader {
        authorize with reader_db_policy
        respond * "reader - hello world!" 200
    }

    route /writer {
        authorize with writer_db_policy
        respond * "writer - hello world!" 200
   }
}

```

Four default sets of credentials are created, two in the file `auth-server/authPasswords.bcup` and two in the LDAP. The Buttercup 
credentials can be modified with the [Buttercup Password Manager](https://buttercup.pw/).  The defaults are:

```
#Buttercup
bcupUser01 / bcupUser01pass
bcupUser02 / bcupUser02pass

#LDAP
user01 / user01pass
user02 / user02pass

# Roles per user:
db_reader: user01, user02, bcupUser01, bcupUser02
db_writer: user02, bcupUser02
```

The auth interface can be tested using `curl`:

```
curl -kv -c cookiejar -H "Content-Type: application/json" -X POST --data '{"xiusername":"bcupUser02", "xipassword":"bcupUser02pass"}' http://localhost:8080/auth
Note: Unnecessary use of -X or --request, POST is already inferred.
*   Trying 127.0.0.1...
* TCP_NODELAY set
* Connected to localhost (127.0.0.1) port 8080 (#0)
> POST /auth HTTP/1.1
> Host: localhost:8080
> User-Agent: curl/7.58.0
> Accept: */*
> Content-Type: application/json
> Content-Length: 58
> 
* upload completely sent off: 58 out of 58 bytes
< HTTP/1.1 200 OK
< Content-Length: 2
< Content-Type: text/plain; charset=utf-8
< Date: Thu, 16 Mar 2023 02:00:27 GMT
< Etag: W/"2-nOO9QiTIwXgNtWtBJezz8kv3SLc"
< Server: Caddy
* cookie size: name/val 11 + 276 bytes
* cookie size: name/val 4 + 1 bytes
* cookie size: name/val 7 + 29 bytes
* cookie size: name/val 8 + 0 bytes
* Added cookie connect.sid="eyJhbGciOiJFUzI1NiIsInR5cCI6IkpXVCJ9.eyJub25jZSI6IllYY3AzWTlfWVBkRkVpM0FmZVB5QmciLCJ1c2VyX2lkIjoiYmN1cFVzZXIwMiIsInJvbGVzIjpbImF1dGhwL3dyaXRlciIsImF1dGhwL3JlYWRlciJdLCJpYXQiOjE2Nzg5MzIwMjd9.lAqNcbl_X4LCbcbAG7b1EsxKwOY62F16E2fXph-FI-shoXIY1Hjo2Hh3pKLwNbqGRuvX_vmEN3DmzO4iJ5DqZg" for domain localhost, path /, expire 1678933827
< Set-Cookie: connect.sid=eyJhbGciOiJFUzI1NiIsInR5cCI6IkpXVCJ9.eyJub25jZSI6IllYY3AzWTlfWVBkRkVpM0FmZVB5QmciLCJ1c2VyX2lkIjoiYmN1cFVzZXIwMiIsInJvbGVzIjpbImF1dGhwL3dyaXRlciIsImF1dGhwL3JlYWRlciJdLCJpYXQiOjE2Nzg5MzIwMjd9.lAqNcbl_X4LCbcbAG7b1EsxKwOY62F16E2fXph-FI-shoXIY1Hjo2Hh3pKLwNbqGRuvX_vmEN3DmzO4iJ5DqZg; Path=/; Expires=Thu, 16 Mar 2023 02:30:27 GMT; HttpOnly
< X-Powered-By: Express
< 
* Connection #0 to host localhost left intact
OK
```

That produces the following JWT payload:

```
{
  "nonce": "YXcp3Y9_YPdFEi3AfePyBg",
  "user_id": "bcupUser02",
  "roles": [
    "authp/writer",
    "authp/reader"
  ],
  "iat": 1678932027
}
```
That cookie in the cookiejar can now be used with the `/reader` and `/writer` access points:
```
curl -kv -b cookiejar -H "Content-Type: application/json" -X GET http://localhost:8080/reader
Note: Unnecessary use of -X or --request, GET is already inferred.
*   Trying 127.0.0.1...
* TCP_NODELAY set
* Connected to localhost (127.0.0.1) port 8080 (#0)
> GET /reader HTTP/1.1
> Host: localhost:8080
> User-Agent: curl/7.58.0
> Accept: */*
> Cookie: connect.sid=eyJhbGciOiJFUzI1NiIsInR5cCI6IkpXVCJ9.eyJub25jZSI6IllYY3AzWTlfWVBkRkVpM0FmZVB5QmciLCJ1c2VyX2lkIjoiYmN1cFVzZXIwMiIsInJvbGVzIjpbImF1dGhwL3dyaXRlciIsImF1dGhwL3JlYWRlciJdLCJpYXQiOjE2Nzg5MzIwMjd9.lAqNcbl_X4LCbcbAG7b1EsxKwOY62F16E2fXph-FI-shoXIY1Hjo2Hh3pKLwNbqGRuvX_vmEN3DmzO4iJ5DqZg
> Content-Type: application/json
> 
< HTTP/1.1 200 OK
< Content-Type: text/plain; charset=utf-8
< Server: Caddy
< Date: Thu, 16 Mar 2023 02:00:51 GMT
< Content-Length: 21
< 
* Connection #0 to host localhost left intact
reader - hello world!

curl -kv -b cookiejar -H "Content-Type: application/json" -X GET http://localhost:8080/writer
Note: Unnecessary use of -X or --request, GET is already inferred.
*   Trying 127.0.0.1...
* TCP_NODELAY set
* Connected to localhost (127.0.0.1) port 8080 (#0)
> GET /writer HTTP/1.1
> Host: localhost:8080
> User-Agent: curl/7.58.0
> Accept: */*
> Cookie: connect.sid=eyJhbGciOiJFUzI1NiIsInR5cCI6IkpXVCJ9.eyJub25jZSI6IllYY3AzWTlfWVBkRkVpM0FmZVB5QmciLCJ1c2VyX2lkIjoiYmN1cFVzZXIwMiIsInJvbGVzIjpbImF1dGhwL3dyaXRlciIsImF1dGhwL3JlYWRlciJdLCJpYXQiOjE2Nzg5MzIwMjd9.lAqNcbl_X4LCbcbAG7b1EsxKwOY62F16E2fXph-FI-shoXIY1Hjo2Hh3pKLwNbqGRuvX_vmEN3DmzO4iJ5DqZg
> Content-Type: application/json
> 
< HTTP/1.1 200 OK
< Content-Type: text/plain; charset=utf-8
< Server: Caddy
< Date: Thu, 16 Mar 2023 02:01:27 GMT
< Content-Length: 21
< 
* Connection #0 to host localhost left intact
writer - hello world!

##
## if the token is left to expire
##

curl -kv -b cookiejar -H "Content-Type: application/json" -X GET http://localhost:8080/writer
Note: Unnecessary use of -X or --request, GET is already inferred.
*   Trying 127.0.0.1...
* TCP_NODELAY set
* Connected to localhost (127.0.0.1) port 8080 (#0)
> GET /writer HTTP/1.1
> Host: localhost:8080
> User-Agent: curl/7.58.0
> Accept: */*
> Content-Type: application/json
> 
< HTTP/1.1 302 Found
< Location: /auth?redirect_url=http%3A%2F%2Flocalhost%3A8080%2Fwriter
< Server: Caddy
< Date: Thu, 16 Mar 2023 02:37:37 GMT
< Content-Length: 5
< Content-Type: text/plain; charset=utf-8
< 
* Connection #0 to host localhost left intact
Found
```

## Performance and Scaling

Since this is an elementary example of an authentication service, it is useful to say a few words about its anticipated performance
and ability to scale.

Caddy has the ability to do multithreading and has been [performance tested relative to recent versions of Nginx](https://blog.tjll.net/reverse-proxy-hot-dog-eating-contest-caddy-vs-nginx/).  While its failure mode behavior and memory usage are a little different than Nginx, 
it should be more than capable of handling the kinds of very simply proxy requests this demonstration creates at rates of hundreds to
thousands per second.

The same is not necessarily true of the authentication service.  The `passport-butterup` Strategy currently re-reads the file every
time it is invoked.  That bottlenecks the performance of the `/auth` REST call because it hits disk whenver the kernel does not have
those blocks cached.  Since the Strategy loads the file into memory, it could be re-written to more actively cache and only re-read 
the file periodically.  It currently dones not, but the outlined use case also specifically states that the Buttercup file is not the 
primary source of authentication traffic.

The proxying of the authentication request to a LDAP request is more scalable.  All the Javascript is actually doing is translating a 
small amount of data from one asynchronous data request to another.  The `passport-ldapauth` plugin also has features for specifying 
the LDAP search query and the filtering of results that can keep that data processing to a minimum.  That should work very well with 
the asynchronous processing model that Javascript uses.  A worker thread implementation is required for NodeJS to handle CPU-heavy tasks. 
Small LDAP requests that process little data do not fall into that category.

Performance during the management of the session data depends on the underlying performance of the session store.  The `express-session` 
does some caching in memory.  Using a directory tree in the `session-file-store` back end does impose the same sort of constraints as 
with the  Buttercup password vault.  The network connected in-memory cache with the `connect-memcached` store has a performance 
characteristic similar to that of the LDAP communication.  As long as the session records are not too big, NodeJS should be able to handle 
the work without need for worker threads.

The design of this demonstration is ameniable to scaling out if that is ever needed.  LDAP servers are generally designed for large scale
use and can be pooled.  The Buttercup file performance is not, for reasons explained, but its use is meant to be limited.  Memcached is
designed to operate cooperatively across multiple instances, and the `connect-memcached` client already can automatically hash entries
across multiple instances.  It doesn't look like memcached instances can be added or removed dynomically, but it is possible to economically 
provision for peak capaacity.

There are three configuration points required to scale deployment.  The first is the Caddy proxy configuration:

```
    route /auth {
        reverse_proxy auth-server:12123
    }
```
This needs to be modified to something that looks more like this:

```
    route /auth {
        reverse_proxy auth-server-auth-demo-1:12123 auth-server-auth-demo-2:12123 {
               lb_policy round-robin
        }
    }
```
Sadly, the number proxy upstreams cannot be set with an environment variable (making the configuration more dynamic) because environment 
variable subsitutions are treated as strings.  An environment variable containing multiple upstreams separated by spaces resovles to a 
single, poorly formatted upstream that fails.  This means that the Caddyfile itself would need to be dynamically modified prior to service 
start.  That's quite possible, but requires some rewriting of the Caddy startup logic in the Dockerfile and elsewhere.

The second touch point is in the `connect-memcached` configuration in the auth-server:

```
var authMemCacheHost = process.env.AUTH_MEMCACHE_HOST || '127.0.0.1';
var authMemCachePort = process.env.AUTH_MEMCACHE_PORT || '11211';

var memCachedOpts = {
    hosts: [ authMemCacheHost + ':' + authMemCachePort ],
    secret: "ABC. 123. You and me."
}
```
Here the code can be easily configured to turn a single environment variable into the data needed to configure the backend.   The problem
here becomes one more related to networking.  Traffic on the current localhost configuration is guaranteed to be private.  It is 
straightforward to alter that configuration to look like this:

```
var memCachedOpts = {
    hosts: [ 'auth-server-auth-demo-1:12123', 'auth-server-auth-demo-2:12123' ],
    secret: "ABC. 123. You and me."
}
```
The problem is that the Docker compose configuration currently uses two networks: `midtier` and `backend`.  That traffic may end up on 
the `midtier` network when it more securely should end up on a private network.  To ensure that, the `memached` service needs to be 
placed in separate containers in separate containers that communicate with the authentication tier via a new private network.

The last touch point is where the authentication tier sets up the LDAP connection:

```
    "url":"ldap://ldap-server:1389",
```
OpenLDAP 2.4 appears to have multiple methods for synchonizing the contents of multiple LDAP instances.  Load balancing LDAP connections 
appears to be supported by both hardware load balancers and software like [pen](https://github.com/UlricE/pen).

## Future Work

Given that this stack is now deployed on Docker, it makes sense to take the same stack and deploy it on AWS.  Docker and Kubernetes can 
now simplify this problem, but doing it the "old, hard" way could provide a refresher on some core concepts like

- RPM building
- systemctl configuration
- AMI building
- EC2 deployment

# auth-demo Phase II

## Introduction

Given the development of the docker-based solution during the earlier round of development, a natural extension of that project is to deploy
it in the cloud.  One very natural way to accomplish that would be to assign the docker container of each tier to
to a virtual machine or other container, deal with cloud-based security and routing, and call the deployment done.  In fact, this solution
is so popular that services like AWS Fargate or Kubernetes exist to do this in a lightweight and serverless manner.

That is not the route I chose to take however.  While that is a useful exercise in terms of modern cloud deployment, I wanted to reacquaint
myself with certain technical aspects of system management and deployment.  These apsects included software package development and release,
system service control, shell programming, and the basics of cloud security that a serverless approach would easily step over.  The result
is an older and perhaps more granular approach to multi-tier deployment but a useful exercise none the less.

Given the development of the docker-based solution during the earlier round of development, a natural extension of that project is to deploy
it in the cloud.  One very natural way to accomplish that would be to assign the docker container of each tier to
to a virtual machine or other container, deal with cloud-based security and routing, and call the deployment done.  In fact, this solution
is so popular that services like AWS Fargate or Kubernetes exist to do this in a lightweight manner.

I chose not to take that route however.  While Docker in the cloud is a useful exercise, I wanted to reacquaint
myself with certain technical aspects of system management and deployment.  These apsects included software package development and release,
system service control, shell programming, and the basics of cloud security that a serverless approach would easily step over.  The result
is an older and perhaps more granular approach to multi-tier deployment but still a useful learning exercise.


## Design Considerations

The design I settled on has the following features:

1. I use AWS CloudFormation to deploy stacks of virtual machines.  This is done to reacquaint myself with the JSON/YAML-based configuration
methods that Amazon cloud services historically seem to prefer.  At the same time, CloudFormation represented infrastructure that simplified
certain aspects of virtual machine creation much as Docker did.

2. I chose to use Amazon Linux 2023 as the base operating system for all the virtual machines.  The motive was primarily economic -- Amazon
offers it as their first choice for free-tier development.  I also have a long history with RPM-based based distributions such as RedHat and
CentOS distributions, and Amazon Linux allowed me to reacquaint myself with some of those skills.

3. I chose to use systemd to create virtual machine services where possbile for multiple reasons.  First, it's the future where initd scripts
are the past.  Second, it connects to kernel-based performance management capabilities that initd cannot (which were not necessary here, but
it was good to reacquaint myself.)  Last, systemd and supervisord share DNA; translating the supervisord configuration used in the Docker phase
was sraightforward.


4. I deliberately didn't go deep with respect to security by only managing access with AWS security groups.  The Docker approach used multiple
networks to protect traffic and segregate connections.  CloudFormation should allow use of the same approach.  I wanted to get to a
running stack if possible without worrying about creating the additional infrastructure.  Now that it's done, creating the networks should be a
reasonable extension.

The general approach to creating each service tier is as follows:

1. Create an RPM to install the necessary software for each tier.  In the case of the LDAP tier just meant installing and configuring the
existing OpenLDAP service.  For NodeJS, it meant installing a recent version and managing nodejs modules. Caddy is a single, static binary
file; once the work of building it is done, deployment requires a minimal amount of configuration.

2. Put the service RPMs in a RPM repository where they can be installed during virtual machine creation.  The installation of each service is
a lightweight process.  The most time consuming part of the installation is refreshing the RPM repo cache to access the new repository prior
to the initial RPM installation.  That time would be saved by creating a machine image instead, but using an AMI adds the weight of managing
AMIs.  That's a choice to could be made, but this solution is not yet complex enough to require making it.

3. CloudFormation creates collects configuration information and writes out the necessary configuration files.  In general, the information
is passed to services via environment variables.  The systemd `Environment` and `EnvironmentFile` directives make this simple.  In the case of
the auth layer, data is also written into a JSON configuration file.

4. Services generally run at the least level of privilege using specially created accounts.  The configuration information is meant to be
read only by the services since some of it includes passwords and access to security keys.  In this way, compromise of the service means
(at most) the acquisition of some useful information.  It does not allow that information to be replaced with other, more compromising
information unless the service virtual machine is further compromised... at which point all is potentially lost.

## Implementation Considerations

Replacing the pre-configured LDAP docker container with an OpenLDAP instance was a pain point.  This is partly due to differences in the
LDAP schemas of the two implementations.  The Bitnami implementation already had a group mechanism in place -- a single subdirectory called
`ou=users` held both data about users (object type `posixAccount`) and groups of users (object type `groupOfNames`.)  Populating that with
the necessary data involved adding groups that what we want and mapping users to groups.

For historical reasons, I adopted a different schema for the OpenLDAP implementaiton.  Here users and groups are segregated into two
different directories. The users are located in the subdirectory named `ou=People` and the groups are in another subdirectory at a
peer level named `ou=Groups`.  To cut down on the required amount of user metadata, the user entries of type inetOrgPerson.  To more
tightly control the user groups, the group entries are of type groupOfUniqueNames that use memberof and reiInt overlays to make sure
that users in the groups actually exist.  The schema setup is also more complex, with an additional group (called `cn=Administrators`)
of users that can modify the LDAP schema.

These changes produce the result that Customizing an OpenLDAP service instance is a procedure that requires approximately thirteen steps:

1. Installing the necessary LDAP software packages (unimplemented because it is handled by CloudFormation).

2. Create a temporary encrypted password to access the LDAP instance during setup.

3. Enable and start the systemd OpenLDAP service.

4. Change the domain distinguished name of the LDAP installation.

5. Install the additional LDAP schemas needed for the user and group object types.

6. Install the memberof overlay.

7. Install the refint overlay.

8. Create our LDAP directory hierarchy, including the Reader, Writer, and Administrator groups.

9. Allow the Administrator group to modify the directory.

10. Add LDAP users to ou=Users.

11. Map all the users into their correct initial groups.

12. Set the administrator password to the encrypted version  provided by the setup process.

13. Configure TLS (unimplemented for now.)

The setup script implements each of these steps using a regular series of routine names (step1, step2, step3, etc...)
This makes it easy for the script to accept a comma-separated list of digits to perform a subset of the steps for
development and debugging purposes.

A lesser pain point was generating all the npm modules used by the auth-server layer. This step is necessary because
npm modules can include compiled code in other languages (like C or C++ for Cython interfaces) and that compiled code
can have shared library dependencies in the environment where it needs to run.  This build is more transparently handled
in the Docker implementation by using a multistage build.  The AWS build needs to do this inside an Amazon Linux comtainer.
An Amazon Linux docker container is available, and the builder script can be modified to copy the node module archive to a
location that is mapped to a directory outside the docker container.

The final problem that the AWS implementation had to overcome is building the caddy binary under Amazon Linux. Strictly
speaking, building caddy under Amazon Linux is not absolutely necessary.  It's a single, static binary that, once built, should
be able to run under multiple similar kernel environments.  That should allow me to build it under one relatively modern
Linux docker container and run under Amazon Linux 2023.  Building in a RHEL 8 docker container  might be necessary because
Amazon offers a docker container that requires the security profile to be disabled (docker run `--security-opt seccomp=unconfined`)
to access local networks -- which installing installing software like go requires.  The necessary (`--security-opt`) flag is not
provided to the `docker build` command for good security reasons, meaning that I could not pre-build a Docker container
with the go build environment needed to build caddy.  I would need to install the build environment every
time caddy needed to be built, without leveraging some of the advantages of a Docker file.  Since the Docker implementation
already used a builder script and I wanted to share that script between the Docker- and RPM-based builds. The solution to the
problems of where and how to create the build environment required some thought.

In the end, I chose a wrapper script approach.  A wrapper script creates the build environment in the (Amazon Linux 2023)
docker container and then calls the caddy builder script used by the Docker implementation. The wrapper script command line
parser is constructed in a way that it can pass command line arguments to the caddy builder script. Like the node modules builder
script, the caddy builder script was modified to copy the built copy of caddy to a location mapped to directory outside the
docker container.  Together these two scripts can build caddy inside an Amazon Linux 2023 docker container.

The build of the actual cluster is handled by four CloudFormation templates:

```
./ldap-rpm/ldap-server.template     # configures the ldap tier EC2 instance

./auth-rpm/auth-server.template     # configures the auth tier EC2 instance

./caddy-rpm/caddy-server.template   # configures the caddy tier EC2 instance

./auth-demo.template                # calls the other three templates to create the whole stack

```

`auth-demo.template` assumes that the other three can be accessed via HTTP from a S3 buckets.  Since it is assumed that the bucket may hold
templates for dev, test, and release versions, the bucket is assumed to contain a directory path underneath the root where all three templates
can be found in the same directory.

All the binary, data, and config files installed by the new RPMs are placed under the `/opt/auth-demo` directory with the exception of
the systemd service files.  Those are installed under `/usr/lib/systemd/system`.

## Configuration

The `setup-ldap.sh` script accepts the following environment variables as inputs:

```
LDAP_DOMAIN_DN (default: dc=example,dc=org)
The LDAP domain distinguished name -- used to construct distguished name many directory objects
LDAP_ORG (default: Example Organization)
Used to fill a required field in the domain object at the root of the LDAP directory tree
LDAP_LIB_PATH (default: /usr/lib64/openldap)
Location where overlay libraries can be found
LDAP_DB_NUM (default: 2)
The LDAP database number -- should almost always be 2
LDAP_DB_TYPE (default: mdb)
OpenLDAP database type -- mdb should almost always be used
LDAP_ADMIN_PASSWORD
The {SSHA} encoded version of the LDAP root-level password
LDAP_SETUP_FILE (default: /etc/openldap/setup_complete)
The name of a file that is created (or modified) when the LDAP setup is successful and complete
LDAP_USERS (default: user01,user02)
Comma separated list of usernames to be initially inserted into the LDAP directory
LDAP_PASSWORDS (default: bitnami1,bitnami2)
Comma separated list of passwords that correspond to the values in the list in LDAP_USERS (default matches docker implementation)
LDAP_READER_GROUP (default: dbReaders)
The name given to the LDAP group of users that have database read privileges
LDAP_WRITER_GROUP (default: dbWriters)
The name given to the LDAP group of users that have database write/update privileges
LDAP_ADMIN_GROUP (default: administrators)
The name given to the LDAP group of users that can modify the LDAP itself
LDAP_DB_READERS (default: all users from LDAP_USERS)
The users added to the LDAP_READER_GROUP
LDAP_DB_WRITERS (default: all users from LDAP_USERS)
The users added to the LDAP_WRITER_GROUP
LDAP_ADMINS (default: all users from LDAP_USERS)
The users added to the LDAP_ADMIN_GROUP
```

The `ldap-server.template` accepts the following paramters:

```
KeyName
Name of an existing EC2 KeyPair to enable SSH access to the instance
LdapDBType (default: mdb)
Value passed to LDAP_DB_TYPE
LdapDomainDN (default: dc=example,dc=org)
Value passed to LDAP_DOMAIN_DN
LdapOrg (default: Example Organization)
Value passed to LDAP_ORG
LdapLibPath (default: /usr/lib64/openldap)
Value passed to LDAP_LIB_PATH
LdapDBNum (default: 2)
Value passed to LDAP_DB_NUM
LdapAdminPassword (default: <none>)
Value passed to LDAP_ADMIN_PASSWORD
LdapSetupFile (default: /etc/openldap/setup_complete)
Value passed to LDAP_SETUP_FILE
LdapUsers (default: user01,user02)
Value passed to LDAP_USERS
LdapReaderGroup (default: dbReaders)
Value passed to LDAP_READER_GROUP
LdapWriterGroup (default: dbWriters)
Value passed to LDAP_WRITER_GROUP
LdapAdminGroup (default: administrators)
Value passed to LDAP_ADMIN_GROUP
LdapDBReaders (default: all from LdapUsers)
Value passed to LDAP_DB_READERS
LdapDBWriters (default: all from LdapUsers)
Value passed to LDAP_DB_WRITERS
LdapAdmins (default: all from LdapUsers)
Value passed to LDAP_DB_ADMINS
InstanceType (default: t2.small)
EC2 instance type for the ldap virtual machine
SSHLocation (default: 0.0.0.0/0)
CIDR determining remote access to public IP on ports 22 and 389
S3RpmRepo (default: http://my-rpm-repo.s3-website-us-west-2.amazonaws.com/my-rpm-repo.repo)
The http URL for the S3 bucket that is the rpm repo for the auth-demo-ldap-installer RPM.
```

The `auth-server.template` accepts the following parameters:

```
KeyName
Name of an existing EC2 KeyPair to enable SSH access to the instance
AuthConfigPath (default: /opt/auth-demo/etc/Ec2Config.json)
Value passed to AUTH_CONFIG_PATH
AuthPublicKey (default: /opt/auth-demo/share/auth-server/public-key.pem)
Value passed to AUTH_PUBLIC_KEY
AuthPrivateKey (default: /opt/auth-demo/share/auth-server/private-key.pem)
Value passed to AUTH_PRIVATE_KEY
AuthButtercupMasterPassword (default: srirachaBear)
Value passed to AUTH_BCUP_MASTER_PASSWORD
AuthButtercupGroupName (default: General)
Value passed to AUTH_BCUP_GROUP_NAME
AuthButtercupFile (default: /opt/auth-demo/share/auth-server/authPasswords.bcup)
Value passed to AUTH_BCUP_FILE_NAME
AuthButtercupReaderAttrName (default: db_reader)
Value passed to AUTH_BCUP_DBREADER_NAME
AuthButtercupWriterAttrName (default: db_writer)
Value passed to AUTH_BCUP_DBWRITER_NAME
LdapServerAddr
The IP addr or DNS name of the LDAP server VM
LdapServerSecurityGroupId
The id of the security group created with the ldap server VM to allow access between the auth server and ldap server VMs
LdapDomainDN (default: dc=example,dc=org)
Value corresponding to LDAP_DOMAIN_DN -- needed navigate the LDAP
LdapAdminPassword
The admin password for the LDAP instance.
LdapReaderGroupName (default: dbReaders)
Value corresponding to LDAP_READER_GROUP
LdapWriterGroupName (default: dbWriters)
Value corresponding to LDAP_WRITER_GROUP
InstanceType (default: t1.micro)
EC2 instance type for the ldap virtual machine
SSHLocation (default: 0.0.0.0/0)
CIDR determining remote access to public IP on port 12123
S3RpmRepo (default: http://my-rpm-repo.s3-website-us-west-2.amazonaws.com/my-rpm-repo.repo)
The http URL for the S3 bucket that is the rpm repo for the auth-demo-auth-installer RPM.
```

The `caddy-server.template` accepts the following values:

```
KeyName
Name of an existing EC2 KeyPair to enable SSH access to the instance
JwtSharedKey (default: /opt/auth-demo/etc/public-key.pem)
The path to the public key used to decrypt authentication JWTs -- must match data in file AUTH_PUBLIC_KEY
AuthServerAddr
The IP addr or DNS name of the auth server VM
AuthServerPort (default: 12123)
The TCP port number of the auth server
AuthServerSecurityGroupId
The id of the security group created with the auth server VM to allow access between the caddy server and auth server VMs
InstanceType (default: t1.micro)
EC2 instance type for the ldap virtual machine
SSHLocation (default: 0.0.0.0/0)
CIDR determining remote access to public IP on port 8080
S3RpmRepo (default: http://my-rpm-repo.s3-website-us-west-2.amazonaws.com/my-rpm-repo.repo)
The http URL for the S3 bucket that is the rpm repo for the auth-demo-caddy-installer RPM.
```

The `auth-demo.template` accepts the following values:

```
KeyName
Name of an existing EC2 KeyPair to enable SSH access to all three instances (could be split into three for different keys for different tiers)
TemplateS3Bucket (default: thaining-auth-demo)
The name of the S3 bucket that holds caddy-server.template, auth-server.template, and ldap-server.template
TemplateS3BucketPath (default: release1.0)
The path from the root of the bucket to the directory where caddy-server.template, auth-server.template, and ldap-server.template
TemplateS3BucketRegion (default: us-west-2)
AWS region where the TemplateS3Bucket can be found
LdapDomainDN (default: dc=example,dc=org)
Value passed to ldap-server.template LdapDomainDN and auth-server.template LdapDomainDN
EncryptedLdapAdminPassword
Value passed to ldap-server.template LdapAdminPassword
PlaintextLdapAdminPassword
Value passed to auth-server.template LdapAdminPassword
LdapOrg (default: An Example Organization)
Value passed to ldap-server.template LdapOrg
LdapUsers (default: user01,user02)
Value passed to ldap-server.template LdapUsers
LdapPasswords (default: user01pass, user02pass)
Value passed to ldap-server.template LdapPasswords
LdapReaderGroup (default: dbReaders)
Value passed to ldap-server.template LdapReaderGroup and auth-server.template LdapReaderGroupName
LdapWriterGroup (default: dbWriters)
Value passed to ldap-server.template LdapWriterGroup and auth-server.template LdapWriterGroupName
LdapAdminGroup (default: administrators)
Value passed to ldap-server.template LdapAdminGroup
LdapDBReaders (default: all from LdapUsers)
Value passed to ldap-server.template LdapDBReaders
LdapDBWriters (default: all from LdapUsers)
Value passed to ldap-server.template LdapDBWriters
LdapAdmins (default: all from LdapUsers)
Value passed to ldap-server.template LdapAdmins
AuthButtercupGroupName (default: General)
Value passed to auth-server.template AuthButtercupGroupName
AuthButtercupFile (default: /opt/auth-demo/share/auth-server/authPasswords.bcup)
Value passed to auth-server.template AuthButtercupFile
AuthButtercupReaderAttrName (default: db_reader)
Value passed to auth-server.template AuthButtercupReaderAttrName
AuthButtercupWriterAttrName (default: db_writer)
Value passed to auth-server.template AuthButtercupWriterAttrName
AuthServerPort (default: 12123)
Value passed to caddy-server.template AuthServerPort
```

## Operation


The general procedure for building the stack consists three major tasks: creating the necessary RPM files and making them available
in a private RPM repo; making the CloudFormation templates for each of the stack tiers available via HTTP; and then running the
CloudFormation template for the whole stack. These tasks can be completed using the following steps:

1. Build each of the RPMs necessary for CloudFormation to build the whole stack on EC2.  To build the RPMs, go to the subdirectory
for each service RPM and run the `build-rpm.sh` script there.  This should build all necessary dependencies, including the `caddy`
binary, all the npm modules, and the encryption keys to sign and verify the authentication JWTs.  When modifying and rebuilding the
RPM files, remember to update the `CADDY_RPM_BUILD`, `AUTH_RPM_BUILD`, and `LDAP_RPM_BUILD` variables in the relevant build scripts.

   ```
   cd caddy-rpm && ./build-rpm.sh
   cd ../auth-rpm && ./build-rpm.sh
   cd ../ldap-rpm && ./build-rpm.sh
   cd ..
   ```

2. With the RPMs now built, they need to be signed with a GPG key.  One set of steps required to configure such a key for an
Ubuntu 18 build system can be found in Phase 2 of the document `doc/how-to-set-up-a-s3-rpm-repo.txt`.  Once the key is set
up, the `rpm` command can be used to sign the RPM files as a group.

   ```
   rpm --addsign *-rpm/auth-demo*.rpm
   ```


3. Once the RPMs are signed, they need to be need to put into a private RPM repo accessible via HTTP.  Tools and directories provided
by the project support using an RPM repo in a S3 bucket.  A description of the steps required to create an RPM repo (with a slightly
different procedure to populate it) can be found the document `doc/how-to-set-up-a-s3-rpm-repo.txt`.  The following steps assume
that the bucket has been created, and is accessible using the `aws s3` CLI.  The name of the bucket can be supplied using the S3_BUCKET
environment variable.

   ```
   mv *-rpm/auth-demo*.x86_64.rpm rpm-repo/x86_64 && mv *-rpm/auth_demo*.noarch.rpm rep-repo/noarch
   S3_BUCKET_NAME=my-rpm-repo ./repo-tools/update_repo.sh
   ```

4. Next, the CloudFormation templates for each stack tier need to be made available via HTTP.  The CloudFormation template for the
stack (`auth-demo.template`) assumes that the templates can be found in a S3 bucket. A description of the steps to create the
required bucket to store the nested service templates can be found at `doc/how-to-set-up-a-s3-template-store.txt`.  The following
command can be used to copy the necessary templates to the configured bucket `my-bucket-name` containing the folder `my-bucket-folder`:

   ```
   aws s3 cp *-rpm/*-server.template s3://my-bucket-name/my-bucket-folder
   ```

5. The requirements to run `auth-demo.template` are now met.  That can be loaded and run using the following steps:

   1. On the "Cloudformation > Stacks > Create stack" page, click the "Upload a template file" button.
   2. Click the "Choose file" button and a popup window appears.
   3. Select auth-demo.template and click the Open button.  The popup window closes and S3 URL on
   the Create Stack page is populated.
   4. Click Next.
   5. Enter the bucket name for the template bucket in the TemplateS3Bucket field.
   6. Enter the folder name in the template bucket in the TemplateS3BucketPath field.
   7. Set TemplateS3BucketRegion to the AWS region where the bucket is located.
   8. Set S3RpmRepo to the URL for the `.repo` file created for the RPM repo.
   9. Provide an encrypted LDAP admin password (encrypted in `{SSHA}` by `slappasswd` or similar) in EncryptedLdapAdminPassword.
   10. Provide the corresponding plaintext version of the LDAP admin password in PlaintextLdapAdminPassword.
   11. Provide a `AWS::EC2::KeyPair::KeyName` in KeyName
   12. Provide a more restrictive network CIDR for SSH and LDAP access SSHLocation (optional bu HIGHLY recommended.)
   13. Make any other desirable changes to the default parameters.
   14. Click Next.
   15. Configure any Stack options.
   16. Click Next.
   17. Acknowledge the capabilities that the stack requires.
   18. Click Submit.

Once the stack is built, the CaddyServerURL output can be used to access it:

```
> curl -kv -c cookiejar -H "Content-Type: application/json" -X POST --data '{"xiusername":"user01", "xipassword":"user01pass"}' http://ec2-35-166-67-19.us-west-2.compute.amazonaws.com:8080/auth
Note: Unnecessary use of -X or --request, POST is already inferred.
*   Trying 35.166.67.19...
* TCP_NODELAY set
* Connected to ec2-35-166-67-19.us-west-2.compute.amazonaws.com (35.166.67.19) port 8080 (#0)
> POST /auth HTTP/1.1
> Host: ec2-35-166-67-19.us-west-2.compute.amazonaws.com:8080
> User-Agent: curl/7.58.0
> Accept: */*
> Content-Type: application/json
> Content-Length: 50
> 
* upload completely sent off: 50 out of 50 bytes
< HTTP/1.1 200 OK
< Content-Length: 2
< Content-Type: text/plain; charset=utf-8
< Date: Thu, 04 May 2023 18:10:31 GMT
< Etag: W/"2-nOO9QiTIwXgNtWtBJezz8kv3SLc"
< Server: Caddy
* cookie size: name/val 11 + 271 bytes
* cookie size: name/val 4 + 1 bytes
* cookie size: name/val 7 + 29 bytes
* cookie size: name/val 8 + 0 bytes
* Added cookie connect.sid="eyJhbGciOiJFUzI1NiIsInR5cCI6IkpXVCJ9.eyJub25jZSI6ImM1SjZVWE5qVlRkNElKQzBCc1RneUEiLCJ1c2VyX2lkIjoidXNlcjAxIiwicm9sZXMiOlsiYXV0aHAvd3JpdGVyIiwiYXV0aHAvcmVhZGVyIl0sImlhdCI6MTY4MzIyMzgzMX0.FkiXceEbPddCq5baS0xsBq84s5nREAr4XqDz7HXV-JMNvwlQmWPwq2Q-E8wdKbq01LLLK4Y0F96R_g_aVHePxQ" for domain ec2-35-166-67-19.us-west-2.compute.amazonaws.com, path /, expire 1683225631
< Set-Cookie: connect.sid=eyJhbGciOiJFUzI1NiIsInR5cCI6IkpXVCJ9.eyJub25jZSI6ImM1SjZVWE5qVlRkNElKQzBCc1RneUEiLCJ1c2VyX2lkIjoidXNlcjAxIiwicm9sZXMiOlsiYXV0aHAvd3JpdGVyIiwiYXV0aHAvcmVhZGVyIl0sImlhdCI6MTY4MzIyMzgzMX0.FkiXceEbPddCq5baS0xsBq84s5nREAr4XqDz7HXV-JMNvwlQmWPwq2Q-E8wdKbq01LLLK4Y0F96R_g_aVHePxQ; Path=/; Expires=Thu, 04 May 2023 18:40:31 GMT; HttpOnly
< X-Powered-By: Express
< 
* Connection #0 to host ec2-35-166-67-19.us-west-2.compute.amazonaws.com left intact
> curl -kv -c cookiejar -H "Content-Type: application/json" -X POST --data '{"xiusername":"bcupUser01", "xipassword":"bcupUser01pass"}' http://ec2-35-166-67-19.us-west-2.compute.amazonaws.com:8080/auth
Note: Unnecessary use of -X or --request, POST is already inferred.
*   Trying 35.166.67.19...
* TCP_NODELAY set
* Connected to ec2-35-166-67-19.us-west-2.compute.amazonaws.com (35.166.67.19) port 8080 (#0)
> POST /auth HTTP/1.1
> Host: ec2-35-166-67-19.us-west-2.compute.amazonaws.com:8080
> User-Agent: curl/7.58.0
> Accept: */*
> Content-Type: application/json
> Content-Length: 58
> 
* upload completely sent off: 58 out of 58 bytes
< HTTP/1.1 200 OK
< Content-Length: 2
< Content-Type: text/plain; charset=utf-8
< Date: Thu, 04 May 2023 18:13:49 GMT
< Etag: W/"2-nOO9QiTIwXgNtWtBJezz8kv3SLc"
< Server: Caddy
* cookie size: name/val 11 + 256 bytes
* cookie size: name/val 4 + 1 bytes
* cookie size: name/val 7 + 29 bytes
* cookie size: name/val 8 + 0 bytes
* Added cookie connect.sid="eyJhbGciOiJFUzI1NiIsInR5cCI6IkpXVCJ9.eyJub25jZSI6InVQa1Q2a2xvc2FsN3BEejVsU1ZLRWciLCJ1c2VyX2lkIjoiYmN1cFVzZXIwMSIsInJvbGVzIjpbImF1dGhwL3JlYWRlciJdLCJpYXQiOjE2ODMyMjQwMjl9.rvLS_fUKw64K567X2qpMz856NHLtcsAps3IkLrmTrmX41FJdqIt_vFXmVsCwvbIE8845GgVWTTcgsmljXJI6ag" for domain ec2-35-166-67-19.us-west-2.compute.amazonaws.com, path /, expire 1683225829
< Set-Cookie: connect.sid=eyJhbGciOiJFUzI1NiIsInR5cCI6IkpXVCJ9.eyJub25jZSI6InVQa1Q2a2xvc2FsN3BEejVsU1ZLRWciLCJ1c2VyX2lkIjoiYmN1cFVzZXIwMSIsInJvbGVzIjpbImF1dGhwL3JlYWRlciJdLCJpYXQiOjE2ODMyMjQwMjl9.rvLS_fUKw64K567X2qpMz856NHLtcsAps3IkLrmTrmX41FJdqIt_vFXmVsCwvbIE8845GgVWTTcgsmljXJI6ag; Path=/; Expires=Thu, 04 May 2023 18:43:49 GMT; HttpOnly
< X-Powered-By: Express
< 
* Connection #0 to host ec2-35-166-67-19.us-west-2.compute.amazonaws.com left intact
```

## Future Work

Building on this work could go in several different directions:

- Security here is minimal, so increasing the security of the deployment is a logical step.  The AWS deployment could make better
use of networks like the Docker configuration to segregate traffic.  HTTPS and LDAPS could be used to encrypt traffic at all levels.
- More clould friendly logging (e.g. AWS CloudWatch) would be useful.
- Improvements to the buttercup module to improve performance (caching data in memory) and manipulate file contents.
- Providing a uniform REST interface for managing users and passwords
- Add a database tier behind the `/reader` and `/writer` access points with an expanded REST interface
- Look at converting the Docker containers to something more like AWS Fargate or migrate the stack to Kubernetes
