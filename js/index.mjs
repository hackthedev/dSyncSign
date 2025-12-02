import {promises as fs} from "fs";
import crypto from "crypto";

export class dSyncSign {
    constructor(keyFile = "./privatekey.json") {
        this.KEY_FILE = keyFile;
        this.sigField = "sig";
    }

    canonicalize(x) {
        if (x === null || typeof x !== "object") return x;
        if (Array.isArray(x)) return x.map(v => this.canonicalize(v));
        const out = {};

        for (const k of Object.keys(x).sort()) out[k] = this.canonicalize(x[k]);
        return out;
    }

    stableStringify(obj) {
        return JSON.stringify(this.canonicalize(obj));
    }

    normalizePublicKey(key) {
        return key
            .replace(/\r|\n|\s+/g, '')
            .replace('-----BEGINPUBLICKEY-----', '-----BEGIN PUBLIC KEY-----')
            .replace('-----ENDPUBLICKEY-----', '-----END PUBLIC KEY-----')
            .replace(/-----BEGIN PUBLIC KEY-----/, '-----BEGIN PUBLIC KEY-----\n')
            .replace(/-----END PUBLIC KEY-----/, '\n-----END PUBLIC KEY-----')
            .replace(/(.{64})/g, '$1\n')
            .trim();
    }

    async ensureKeyPair() {
        try {
            const raw = await fs.readFile(this.KEY_FILE, "utf8");
            const {privateKey} = JSON.parse(raw);

            crypto.createPrivateKey(privateKey);

            const pubKey = crypto.createPublicKey(privateKey).export({type: "spki", format: "pem"});
            return {privateKey, publicKey: pubKey.toString()};
        } catch {
            const {privateKey, publicKey} = crypto.generateKeyPairSync("rsa", {
                modulusLength: 2048,
                publicKeyEncoding: {type: "spki", format: "pem"},
                privateKeyEncoding: {type: "pkcs8", format: "pem"}
            });

            await fs.writeFile(this.KEY_FILE, JSON.stringify({privateKey}, null, 2), {encoding: "utf8", mode: 0o600});
            return {privateKey, publicKey};
        }
    }

    async getPrivateKey() {
        const {privateKey} = await this.ensureKeyPair();
        return privateKey;
    }

    async getPublicKey() {
        const {publicKey} = await this.ensureKeyPair();
        return publicKey;
    }

    async encrypt(data, recipient) {
        const plaintext = typeof data === "string" ? data : this.stableStringify(data);
        let aesKey;
        let envelope = {method: ""};

        if (recipient.includes("BEGIN PUBLIC KEY") || recipient.includes("BEGIN RSA PUBLIC KEY")) {
            aesKey = crypto.randomBytes(32);
            envelope.method = "rsa";
            envelope.encKey = crypto.publicEncrypt(
                {key: recipient, padding: crypto.constants.RSA_PKCS1_OAEP_PADDING},
                aesKey
            ).toString("base64");
        } else {
            const salt = crypto.randomBytes(16);
            aesKey = crypto.pbkdf2Sync(recipient, salt, 100000, 32, "sha256");
            envelope.method = "password";
            envelope.salt = salt.toString("base64");
        }

        // Standard-konformer 12-Byte-IV (statt 16)
        const iv = crypto.randomBytes(12);

        const cipher = crypto.createCipheriv("aes-256-gcm", aesKey, iv);
        const ciphertext = Buffer.concat([cipher.update(plaintext, "utf8"), cipher.final()]);
        const tag = cipher.getAuthTag();

        return {
            ...envelope,
            iv: iv.toString("base64"),
            tag: tag.toString("base64"),
            ciphertext: ciphertext.toString("base64")
        };
    }

    async decrypt(envelope, password = null) {
        let aesKey;
        if (envelope.method === "rsa") {
            const priv = await this.getPrivateKey();
            aesKey = crypto.privateDecrypt(
                {key: priv, padding: crypto.constants.RSA_PKCS1_OAEP_PADDING},
                Buffer.from(envelope.encKey, "base64")
            );
        } else if (envelope.method === "password") {
            if (!password) throw new Error("Password required for password-based decryption");
            aesKey = crypto.pbkdf2Sync(
                password,
                Buffer.from(envelope.salt, "base64"),
                100000,
                32,
                "sha256"
            );
        } else {
            throw new Error("Unsupported envelope method");
        }

        const iv = Buffer.from(envelope.iv, "base64");
        const tag = Buffer.from(envelope.tag, "base64");
        const ciphertext = Buffer.from(envelope.ciphertext, "base64");

        const decipher = crypto.createDecipheriv("aes-256-gcm", aesKey, iv);
        decipher.setAuthTag(tag);

        const dec = Buffer.concat([decipher.update(ciphertext), decipher.final()]);
        const txt = dec.toString("utf8");
        try {
            return JSON.parse(txt);
        } catch {
            return txt;
        }
    }

    async signData(data) {
        const priv = await this.getPrivateKey();
        const signer = crypto.createSign("SHA256");
        const payload = typeof data === "string" ? data : this.stableStringify(data);

        signer.update(payload, "utf8");
        signer.end();

        return signer.sign(priv, "base64");
    }

    verifyData(data, signature, publicKey) {
        const verifier = crypto.createVerify("SHA256");
        const payload = typeof data === "string" ? data : this.stableStringify(data);

        verifier.update(payload, "utf8");
        verifier.end();

        return verifier.verify(publicKey, signature, "base64");
    }

    getByPath(root, path) {
        if (!path) return root;
        const re = /([^.\[\]]+)|\[(\d+)\]/g;
        const parts = [];
        let m;

        while ((m = re.exec(path)) !== null) parts.push(m[1] !== undefined ? m[1] : Number(m[2]));
        let cur = root;

        for (const p of parts) {
            if (cur == null) return undefined;
            cur = cur[p];
        }
        return cur;
    }

    cloneWithoutSig(obj) {
        if (obj == null || typeof obj !== "object") return obj;
        let copy;

        if (typeof structuredClone === "function") {
            try {
                copy = structuredClone(obj);
            } catch {
                copy = JSON.parse(JSON.stringify(obj));
            }
        } else {
            copy = JSON.parse(JSON.stringify(obj));
        }

        if (copy && Object.prototype.hasOwnProperty.call(copy, this.sigField)) delete copy[this.sigField];
        return copy;
    }

    async signJson(targetOrRoot, path) {
        let target = path ? this.getByPath(targetOrRoot, path) : targetOrRoot;

        if (target == null) {
            if (path) return false;
            throw new TypeError("target required");
        }

        if (Array.isArray(target)) {
            const out = [];
            for (const item of target) {
                if (item == null || typeof item !== "object") {
                    out.push(null);
                    continue;
                }
                if (Object.prototype.hasOwnProperty.call(item, this.sigField)) {
                    out.push(item[this.sigField]);
                    continue;
                }
                const payload = this.cloneWithoutSig(item);
                const s = await this.signData(payload);

                item[this.sigField] = s;
                out.push(s);
            }
            return out;
        }

        if (typeof target === "object") {
            if (Object.prototype.hasOwnProperty.call(target, this.sigField)) return target[this.sigField];
            const payload = this.cloneWithoutSig(target);
            const s = await this.signData(payload);

            target[this.sigField] = s;
            return s;
        }
        throw new TypeError("target must be object or array");
    }

    async verifyJson(targetOrRoot, publicKeyOrGetter, path) {
        let target = path ? this.getByPath(targetOrRoot, path) : targetOrRoot;

        if (target == null) {
            if (path) return false;
            throw new TypeError("target required");
        }

        if (Array.isArray(target)) {
            const out = [];

            for (const item of target) {
                if (item == null || typeof item !== "object") {
                    out.push(false);
                    continue;
                }

                if (!Object.prototype.hasOwnProperty.call(item, this.sigField)) {
                    out.push(false);
                    continue;
                }

                const signature = item[this.sigField];
                let pub = publicKeyOrGetter;

                if (typeof publicKeyOrGetter === "function") pub = await publicKeyOrGetter(item, targetOrRoot);
                if (!pub) {
                    out.push(false);
                    continue;
                }

                const payload = this.cloneWithoutSig(item);
                out.push(Boolean(this.verifyData(payload, signature, pub)));
            }
            return out;
        }
        if (typeof target === "object") {
            if (!Object.prototype.hasOwnProperty.call(target, this.sigField)) return false;

            const signature = target[this.sigField];
            let pub = publicKeyOrGetter;

            if (typeof publicKeyOrGetter === "function") pub = await publicKeyOrGetter(target, targetOrRoot);
            if (!pub) return false;

            const payload = this.cloneWithoutSig(target);
            return Boolean(this.verifyData(payload, signature, pub));
        }
        throw new TypeError("target must be object or array");
    }
}
