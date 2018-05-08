# Falcon Auth0 Authorization Middleware
Auth0 Authorization Middleware for The Falcon Web Framework

# Install
Install through pip via
```bash
$ pip install falcon-auth0
```

# Usage
You will need to supply a Dictionary containing Auth0 settings. These configurations can be supplied in two different
ways. For the average user, you can supply a Dictionary of String keys and String values, such as:
```python
cfg = {
    'alg': ['RS256'],
    'audience': 'my.app.name.auth0.com/userinfo',
    'domain': 'my.app.name.auth0.com', # or 'https://my.app.name.auth0.com/'
    'jwks_uri': 'https://my.app.name.auth0.com/.well-known/jwks.json'
}
```
If your application has multiple environments (Development, Test, QA, User Acceptance, Production), you may supply a
Dictionary of String environment keys and Dictionary values of String keys with String Values, such as:
```python
cfg = {
    'dev': {
        'alg': ['RS256'],
        'audience': 'my.dev.environment.auth0.com/userinfo',
        'domain': 'my.dev.environment.auth0.com', # or 'https://my.dev.environment.auth0.com/'
        'jwks_uri': 'https://my.dev.environment.auth0.com/.well-known/jwks.json'
    },
    'test': {
        'alg': ['RS256'],
        'audience': 'my.test.environment.auth0.com/userinfo',
        'domain': 'my.test.environment.auth0.com', # or 'https://my.test.environment.auth0.com/'
        'jwks_uri': 'https://my.test.environment.auth0.com/.well-known/jwks.json'
    },
    'uat': {
        'alg': ['RS256'],
        'audience': 'my.uat.environment.auth0.com/userinfo',
        'domain': 'my.uat.environment.auth0.com', # or 'https://my.uat.environment.auth0.com/'
        'jwks_uri': 'https://my.uat.environment.auth0.com/.well-known/jwks.json'
    },
    'prod': {
        'alg': ['RS256'],
        'audience': 'my.prod.environment.auth0.com/userinfo',
        'domain': 'my.prod.environment.auth0.com', # or 'https://my.prod.environment.auth0.com/'
        'jwks_uri': 'https://my.prod.environment.auth0.com/.well-known/jwks.json'
    }
}
```

Once complete, you'll inject the middleware directly into Falcon's `falcon.API([...,Auth0Middleware(cfg),...])`.