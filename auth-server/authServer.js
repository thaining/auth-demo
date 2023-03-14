// set up jquery 
var jsdom = require("jsdom");

const { JSDOM } = jsdom;
const { window } = new JSDOM();

var jQuery = require('jquery')(window);

// set up header, cookie, and body parsing
var bodyParser = require('body-parser');
var cookieParser = require('cookie-parser');
var fs = require('fs');

// set up http and the express middleware
var http = require('http');
var express = require('express');
var session = require('express-session-jwt');
var MemcachedStore = require('connect-memcached')(session);
var FileStore = require('session-file-store')(session);
var HTTPStatus = require('http-status');
var app = express();

// set up the passport middleware
var passport = require('passport');
var LdapStrategy = require('passport-ldapauth');
var ButtercupStrategy = require('passport-buttercup');

// load miscellaneous packages
const path = require('path');
var Validator = require('jsonschema').Validator;

// read environment variables
var configJsonPath = process.env.AUTH_CONFIG_PATH || __dirname + path.sep + 'dockerConfig.json';
var publicKeyPath = process.env.AUTH_PUBLIC_KEY || __dirname + path.sep + 'public-key.pem';
var privateKeyPath = process.env.AUTH_PRIVATE_KEY || __dirname + path.sep + 'private-key.pem';
var authFileStorePath = process.env.AUTH_FILE_STORE_PATH || '/tmp/session';
var authUserField = process.env.AUTH_USER_FIELD || 'xiusername';
var authPasswordField = process.env.AUTH_PASSWORD_FIELD || 'xipassword';
var authBcupMasterPassword = process.env.AUTH_BCUP_MASTER_PASSWORD;
var authBcupGroupName = process.env.AUTH_BCUP_GROUP_NAME || 'General';
var authBcupFileName = process.env.AUTH_BCUP_FILE_NAME;
var authMemCacheHost = process.env.AUTH_MEMCACHE_HOST || '127.0.0.1';
var authMemCachePort = process.env.AUTH_MEMCACHE_PORT || '11211';
var authServerProxyPort = process.env.AUTH_SERVER_PROXY_PORT || '12123';
var authBcupDbReaderName = process.env.AUTH_BCUP_DBREADER_NAME || 'db_reader';
var authBcupDbWriterName = process.env.AUTH_BCUP_DBWRITER_NAME || 'db_writer';
var authSessionCacheStoreType = process.env.AUTH_SESSION_STORE_TYPE || 'memcacheStore';
var validCacheStoreTypes = [ 'memcacheStore', 'fileStore' ];

if (!validCacheStoreTypes.includes(authSessionCacheStoreType)) {
    console.log("The AUTH_SESSION_STORE_TYPE " + authSessionCacheStoreType + " is not valid. Valid types: " + JSON.stringify(validCacheStoreTypes) + " Exiting...");
    process.exit();
}

// read configuration files
var serviceConfig = {
    "ldapConfig": "",
    "publicKey": "",
    "privateKey": ""
};

class ConfigFileReader {
    constructor(key, name, description, outputObj) {
        this.key = key;
        this.name = name;
        this.description = description;
        this.outputObj = outputObj;
    }

    post() { }

    valid() {
        if (!(this.key in this.outputObj)) {
                console.log("The config key " + this.key + " connnot be found in the config object.  Exiting...");
            process.exit();
        }
    }

    read() {
        this.valid();

        if (fs.existsSync(this.name)) {
            this.outputObj[this.key] = fs.readFileSync(this.name);
            this.post();
        } else {
            console.log("The " + this.description + " file " + this.name +
                        " does not exist.  Exiting...");
            process.exit();
        }
    }
}

class JsonConfigReader extends ConfigFileReader {

    post() {
        super.post();
        this.outputObj[this.key] = JSON.parse(this.outputObj[this.key]);
    }
}

class LdapConfigFileReader extends JsonConfigReader {
    constructor(key, name, description, outputObj, schema) {
        super(key, name, description, outputObj);
        this.schema = schema;
    }

    post() {
        super.post();
        var v = new Validator();
        var result = v.validate(this.outputObj[this.key], this.schema);

        if (! result.valid) {
            console.log("The file " + this.name + " is not valid: " + JSON.stringify(result.errors));
            console.log("Exiting...");
            process.exit();
        }
    }
}

const ldapConfigSchema = {
    "$schema": "https://json-schema.org/draft/2020-12/schema",
    "$id": "https://example.com/product.schema.json",
    "title": "auth server config file spec",
    "description": "describing the contents of a an auth server config file",
    "type": "object",
    "properties": {
        "url": {
            "description": "the URL of the ldap server",
            "type": "string"
        },
        "bindDN": {
            "description": "the LDAP bind destinguished name",
            "type": "string",
        },
        "bindCredentials": {
            "description": "the password for the LDAP bindDN",
            "type": "string"
        },
        "searchBase": {
            "description": "the base LDAP path for searching for users",
            "type": "string"
        },
        "searchFilter": {
            "description": "the filter used to indentify usernames under the searchBase",
            "type": "string"
        },
        "searchScope": {
            "description": "the scope of the search under searchBase",
            "type": "string",
            "enum": [ "base", "one", "sub" ]
        },
        "groupSearchBase": {
            "description": "the base LDAP path for searching for user groups",
            "type": "string"
        },
        "groupSearchFilter": {
            "description": "the filter used to indentify group membership under the groupSearchBase",
            "type": "string"
        },
        "tlsOptions": {
            "description": "options for the NodeJS tls module for LDAPS",
            "type": "object"
        },
        "groupSearchScope": {
            "description": "the scope of the search under groupSearchBase",
            "type": "string",
            "enum": [ "base", "one", "sub" ]
        },
        "dbReaderGroup": {
            "description": "the name of the group of db readers",
            "type": "string"
        },
        "dbWriterGroup": {
            "description": "the name of the group of db writers",
            "type": "string"
        }
    },
    "required": [ "url", "bindDN", "bindCredentials", "searchBase", "searchFilter",
                  "groupSearchBase", "groupSearchFilter",
                  "groupSearchAttributes", "dbReaderGroup",
                  "dbWriterGroup" ]
}

const ldapConfigReader = new LdapConfigFileReader("ldapConfig", configJsonPath, "LDAP config file",
                                                  serviceConfig, ldapConfigSchema);
const publicKeyReader = new ConfigFileReader("publicKey", publicKeyPath, "JWT public key", serviceConfig);
const privateKeyReader = new ConfigFileReader("privateKey", privateKeyPath, "JWT private key", serviceConfig);

ldapConfigReader.read();
publicKeyReader.read();
privateKeyReader.read();

var strictSecurity = false;

// configure express-session

function jwtFromReq(req) {
    var roles = [];
    if (req.user) {
        if (req.user.dbWriter) {
            roles.push("authp/writer");
        }
        if (req.user.dbReader) {
            roles.push("authp/reader");
        }
    }

    return req.user ? {
        "user_id": req.user.uid,
        "roles": roles
    } : null;
}

var fileStoreOptions = {
    path: authFileStorePath
};

var memCachedOpts = {
    hosts: [ authMemCacheHost + ':' + authMemCachePort ],
    secret: "ABC. 123. You and me."
}

var sessionStore;

if (authSessionCacheStoreType == "memCacheStore") {
    sessionStore = new MemcachedStore(memCachedOpts);
} else {
    sessionStore = new FileStore(fileStoreOptions);
}

var sessionOpts = {
    saveUninitialized: true,
    resave: false,
    store: sessionStore,
    secret: 'keyboard cat',
    cookie: { maxAge: 1800000 },
    keys: { public: serviceConfig["publicKey"], private: serviceConfig["privateKey"] },
    jwtFromReq: jwtFromReq
};

// configure passport and the authentication process
passport.serializeUser(function(user, done) {
    done(null, user);
});

passport.deserializeUser(function(id, done) {
    done(null, id);
});

passport.use(new LdapStrategy({
    server: serviceConfig["ldapConfig"],
    usernameField: authUserField,
    passwordField: authPasswordField
}, function(profile, done) {
    var dbReader = false;
    var dbWriter = false;

    if (profile._groups && typeof profile._groups == 'object') {
        for (i = 0; i < profile._groups.length; i++) {
            console.log('****** dn: ' + profile._groups[i]);
            if (profile._groups[i].cn == serviceConfig["ldapConfig"].dbReaderGroup) {
                dbReader = true;
            }
            if (profile._groups[i].cn == serviceConfig["ldapConfig"].dbWriterGroup) {
                dbWriter = true;
            }
        }
    }

    profile.dbReader = dbReader;
    profile.dbWriter = dbWriter;

    return done(null, profile);
}));


var buttercupProperties = {};
buttercupProperties[authBcupDbReaderName] = 'boolean';
buttercupProperties[authBcupDbWriterName] = 'boolean';

passport.use(new ButtercupStrategy({
    filename: authBcupFileName,
    masterPassword: authBcupMasterPassword,
    usernameField: authUserField,
    passwordField: authPasswordField,
    groupName: authBcupGroupName,
    propertyDictObject: buttercupProperties
}, function(profile, done) {
    if ('undefined' !== typeof profile.buttercup.username) {
        var properties = { "db_writer": "dbWriter",
                           "db_reader": "dbReader" };
        profile.uid = profile.buttercup.username;

        Object.keys(properties).forEach(propertyName => {
            if ('undefined' !== typeof profile.buttercup[propertyName]) {
                profile[properties[propertyName]] = profile.buttercup[propertyName];
            }
        });
        return done(null, profile);
    } else {
        return done(null, false);
    }
}));


var authenticationStrategies = ['ldapauth', 'buttercup'];

var opts = { failWithError: false };

function processErrorInfo(info) {
    var buf = "";
    var line = "";

    if (typeof info === 'object') {
        for (i = 0; i < info.length; i++) {
            if (typeof info[i] === 'object') {
                line = authenticationStrategies[i] + ': ' + JSON.stringify(info[i]);
            } else {
                line = authenticationStrategies[i] + ': ' + info[i];
            }
            buf += ' ' + line;
            console.log(' ' + (i+1) + ' ' + line);
        }
    }

    return buf;
}

function safe_authenticate(req, res, next) {
    passport.authenticate(authenticationStrategies, opts, function(err, user, info) {
        var username = req.body['xiusername'] || req.query['xiusername'];

        if (err) {
            console.log("Authentication error for username: " + username);
            console.log(err.message);
            res.status(HTTPStatus.UNAUTHORIZED).send('Error communicating with Active Directory:' + err.message);
            return;
        }
        if (!user) {
            console.log("Authentication failure for username: " + username);
            var errMsg = processErrorInfo(info);
            res.status(HTTPStatus.UNAUTHORIZED).send("User authentication failed: " + errMsg);
            return;
        }
        req.logIn(user, function(err) {
            if (err) {
                res.status(HTTPStatus.UNAUTHORIZED).send("Error creating session");
                return;
            }
            next();
        });
    })(req, res, next);
}

// configure express
app.use(bodyParser.urlencoded({extended:false}));
app.use(bodyParser.json());
app.use(cookieParser(sessionOpts.secret));
app.use(session(sessionOpts));
app.use(passport.initialize());
app.use(passport.session());


// create REST interface
app.get('/', function(req, res) {
    res.send('Random factoid on the internet: You owe jyang $5');
});

app.post('/auth', [safe_authenticate], function(req, res, next) {
             var expirationDate = new Date(req.session.cookie.expires);
             var stuff = req.body;
             // console.log("I just received a request: " + JSON.stringify(stuff));
             console.log("session: " + JSON.stringify(req.session));
             console.log("sessionID: " + JSON.stringify(req.sessionID));
             console.log("expiration: " + expirationDate.getTime());
             if (req.headers.cookie) {
                 console.log("request cookie: " + encodeURIComponent(cookie.parse(req.headers.cookie)['connect.sid']).toString());
             }
             res.sendStatus(HTTPStatus.OK);
         }, function (err) {
             res.status(HTTPStatus.UNAUTHORIZED).send('Not Authenticated');
         });


// start HTTP server
var httpServer = http.createServer(app);

httpServer.listen(authServerProxyPort, function() {
        console.log("I am listening on port " + authServerProxyPort);
});
