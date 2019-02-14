import { DDNSChallenger } from "../src";
import { assert } from "chai";
import randomstring = require('randomstring');

// cloudflare credentials should be set before test
assert(process.env.DNS_CLOUDFLARE_USER, 'DNS_CLOUDFLARE_USER is required in env');
assert(process.env.DNS_CLOUDFLARE_TOKEN, 'DNS_CLOUDFLARE_TOKEN is required in env');

const creds = {
  dns: "cloudflare",
};

const domain = "test.uugo.xyz";
const challenge = "xxx-acme-challenge-xxx";
const keyAuthorization = randomstring.generate();

describe("DDNSChallenger", function() {
  this.timeout(30000);

  it("should work with ddns", async () => {
    const challenger = new DDNSChallenger({
      test: "_test_01"
    });
    await challenger.test({ ...creds }, domain, challenge, keyAuthorization);
  });
});
