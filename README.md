lebot-challenge-ddns
----

[![Greenkeeper badge](https://badges.greenkeeper.io/taoyuan/lebot-challenge-ddns.svg)](https://greenkeeper.io/)

> A dns-based strategy for `node-letsencrypt` for setting based on [namex](github.com/taoyuan.namex), retrieving,
and clearing ACME DNS-01 challenges issued by the ACME server
>
> It creates a subdomain record for `_acme-challenge` with `keyAuthDigest`
to be tested by the ACME server.
>
> ```
> _acme-challenge.example.com   TXT   xxxxxxxxxxxxxxxx    TTL 60
> ```
>
> * Safe to use with node cluster
> * Safe to use with ephemeral services (Heroku, Joyent, etc)

## Installation

```bash
npm i lebot-challenge-ddns
```

## Usage

```typescript
import {DDNSChallenger} from "lebot-challenge-ddns";

const challenge = DDNSChallenger.create({
  user: 'john.doe@example.com',
  token: '...',
  ttl: 60,

  debug: false,
});

import LE = require('letsencrypt');

LE.create({
  server: LE.stagingServerUrl,                               // Change to LE.productionServerUrl in production
  challengeType: 'dns-01',
  challenges: {
    'dns-01': challenge
  },
  approveDomains: [ 'example.com' ]
});
```

NOTE: If you request a certificate with 6 domains listed,
it will require 6 individual challenges.

## Exposed Methods

For ACME Challenge:

* `set(opts, domain, challange, keyAuthorization, done)`
* `get(opts, domain, challenge, done)`
* `remove(opts, domain, challenge, done)`

Note: `get()` is a no-op for `dns-01`.

For `node-letsencrypt` internals:

* `getOptions()` returns the internal defaults merged with the user-supplied options
* `loopback(opts, domain, challange, done)` performs a dns lookup of the txt record
* `test(opts, domain, challange, keyAuthorization, done)` runs set, loopback, remove, loopback

