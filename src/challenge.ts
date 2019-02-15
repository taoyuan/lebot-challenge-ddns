import assert = require("assert");
import PromiseA = require("bluebird");
import { Bucket, Store } from "kvs";
import { Executor } from "namex";
import dns = require("dns");
import retry = require("async-retry");

const DEFAULT_OPTIONS = {
  acmeChallengeDns: "_acme-challenge"
};

type CallbackFn = (err: any, data?: any) => void;

interface ChallengeOptions {
  acmeChallengeDns?: string;
  ttl?: number;
  user?: string;
  pass?: string;
  token?: string;
  store?: string | { [name: string]: any } | Store;
  debug?: boolean;
  test?: string;
  logger?
}

interface DDNSChallengeOptions extends ChallengeOptions {
  dns: string;
}

interface DDNSChallengeArgs extends ChallengeOptions {
  dns?: string;
}

export = class DDNSChallenge {

  protected opts: DDNSChallengeOptions;
  protected store: Store;
  protected bucket: Bucket;
  protected ready: Promise<void>;

  static create(args: DDNSChallengeArgs) {
    return new DDNSChallenge(args);
  }

  constructor(args?: DDNSChallengeArgs) {
    const opts = Object.assign({}, DEFAULT_OPTIONS, args);

    this.opts = <DDNSChallengeOptions>opts;
    let store: any = opts.store || "memory";
    if (store instanceof Store) {
      this.store = store;
    } else {
      this.store = Store.create(store);
    }

    this.ready = this.init();
  }

  async init() {
    this.bucket = await this.store.createBucket("lebot-ddns");
  }

  getOptions() {
    return this.opts;
  }

  async set(args: { [name: string]: any }, domain: string, challenge: string, keyAuthorization?: string | null, done?: CallbackFn) {
    try {
      await this.ready;

      const opts = Object.assign({}, this.opts, args);

      assert(opts.dns, "`dns` provider is required.");

      const keyAuthDigest = require("crypto").createHash("sha256").update(keyAuthorization || "").digest("base64")
        .replace(/\+/g, "-")
        .replace(/\//g, "_")
        .replace(/=+$/g, "");
      const challengeDomain = buildChallengeDomain(domain, opts.acmeChallengeDns, opts.test);

      if (!keyAuthorization) {
        console.warn("SANITY FAIL: missing keyAuthorization", domain, keyAuthorization);
      }

      const creds = {
        user: opts.user,
        pass: opts.pass,
        token: opts.token
      };

      await this.bucket.set(domain, creds);

      await Executor.execute(opts.dns, "update", challengeDomain, {
        ...creds,
        type: "TXT",
        name: challengeDomain,
        ttl: opts.ttl || 120,
        content: keyAuthDigest
      });

      if (opts.debug) {
        console.log("Test DNS Record:");
        console.log("dig TXT +noall +answer @ns1.redirect-www.org '" + challengeDomain + "' # " + challenge);
      }

      await retry(async () => assert((await this.loopback(opts, domain)).includes(keyAuthDigest)), { maxTimeout: 5000 });

      done && done(null, keyAuthDigest);
      return keyAuthDigest;
    } catch (e) {
      console.error(e);
      done && done(e);
      return PromiseA.reject(e);
    }
  }

  get(args, domain, challenge, done) {
    done = null; // nix linter error for unused vars
    throw new Error("Challenge.get() does not need an implementation for dns-01. (did you mean Challenge.loopback?)");
  }

  async remove(args: { [name: string]: any }, domain: string, challenge: string, done?: CallbackFn) {
    try {
      await this.ready;

      const opts = Object.assign({}, this.opts, args);

      assert(opts.dns, "`dns` provider is required.");

      const creds = await this.bucket.get(domain);
      if (!creds) {
        console.warn("[warning] could not remove '" + domain + "': already removed");
        done && done(null);
        return;
      }

      const challengeDomain = buildChallengeDomain(domain, opts.acmeChallengeDns, opts.test);

      await Executor.execute(opts.dns, "delete", challengeDomain, {
        ...creds,
        name: challengeDomain,
        type: "TXT"
      });

      done && done(null);

      await await this.bucket.del(domain);
    } catch (e) {
      console.error(e);
      done && done(e);
      return PromiseA.reject(e);
    }
  }

  async loopback(args: { [name: string]: any }, domain: string, done?: CallbackFn): Promise<string[]> {
    const opts = Object.assign({}, this.opts, args);
    const challengeDomain = buildChallengeDomain(domain, opts.acmeChallengeDns, opts.test);
    try {
      const records = <string[][]> await PromiseA.fromCallback(cb => dns.resolveTxt(challengeDomain, cb));
      const answer = records.map(record => record.join(""));
      done && done(null, answer);
      return answer;
    } catch (e) {
      console.error(e);
      done && done(e);
      return PromiseA.reject(e);
    }
  }

  async test(args: { [name: string]: any }, domain: string, challenge: string, keyAuthorization?: string | null, done?: CallbackFn) {
    args = args || {};
    args.test = args.test || this.opts.test || "_test";

    const opts = { ...DEFAULT_OPTIONS, ...args };

    try {
      const keyAuthDigest = await this.set(opts, domain, challenge, keyAuthorization);
      const records = await this.loopback(opts, domain);
      await this.remove(opts, domain, challenge);
      checkChallenge(records, keyAuthDigest);
    } catch (e) {
      console.error(e);
      done && done(e);
      return PromiseA.reject(e);
    }
  }
}

function buildChallengeDomain(domain: string, prefix?: string, test?: string) {
  return prefixify(test) + prefixify(prefix) + domain.replace(/^\*\./, "");
}

function prefixify(name?: string) {
  if (!name) {
    return "";
  } else {
    return name[name.length] === "." ? name : name + ".";
  }
}

function checkChallenge(records: string[], expected: string) {
  if (!records.some(k => k == expected)) {
    throw new Error("TXT record '" + records + "' doesn't match '" + expected + "'");
  }
}
