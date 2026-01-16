# dSyncSign

> [!WARNING]
>
> This repo wont be continued and has been moved to an org:  
> https://github.com/NETWORK-Z-Dev/dSyncSign

dSyncSign is an additional package that comes with a few helper functions that can enhance the plain dSync package. dSyncSign comes with the following features:

- Creation of a private key file and public key
- Ability to sign strings or json objects, or even nested objects inside a json object
- Ability to verify signed strings/objects using a known public key
- Ability to encrypt and decrypt data with a private key or password

------

## Importing

You can import the package with the following line into your code and install it like below

```js
import { dSyncSign } from "@hackthedev/dsync-sign";

const signer = new dSyncSign("./mykeys.json"); // optional path for private key file
```

```sh
npm i @hackthedev/dsync-sign
```

------

## Signing & Verifying JSON Objects

You can also sign and very JSON objects pretty easily.

```js
const obj = { hello: "world" };
await signer.signJson(obj);
console.log("Object with sig", obj);

const verified = await signer.verifyJson(obj, await signer.getPublicKey());
console.log("JSON valid?", verified);
```

Output:

```sh
Object with sig {
  hello: 'world',
  sig: 'W3tGrkWdCT62Zc7eJKM2Pr13CgsQc65diH4N5d0pGasyKEpWQVZG5wz6WhlKoJmYqE8O4OSIcm/WVCBtnZM66zpic0PAtuGaTKt224AO/zDWrQhuCDflvR29OHzeKcnHXNVS924PXK24dA2MiILTYlSbGLguIw0bfIWN1hDeVHYWu3VeDmOSBFUlkaviJzxV/lALRSBySIDd5SFFQQWfk0hLv0Hy8MMHzGQetrs9/l5mBLGU8iSrA85alXFN+OKz0Qo57zgPV5cBCl19LB/ZL0oR+GsQv171Jn04UO8hFUsyJJqI2VnPAw11LgPqwXqHUDuQwdCS7zvTyDmlM7+rvA=='
}
JSON valid? true
```

------

## Verifying & Signing nested JSON Objects

Its also possible to sign nested or specific objects.

```js
const obj = {
    hello: {
        world: "hi"
    },
    bye: {
        crazy: "indeed"
    }
};
await signer.signJson(obj.hello);
console.log("Object with sig", obj);

const verified = await signer.verifyJson(obj.hello, await signer.getPublicKey());
console.log("JSON valid?", verified);
```

Output:

```sh
Object with sig {
  hello: {
    world: 'hi',
    sig: 'qEsJ8O7HVohexEFpvjVljfvSXdPp93DHAcg1PiLxNA0TjE48FdHd11cS5vYJlLPmpPEG/80cqETsHwlCjTiOZI6xC90IxdGTKGttjv1gFYM5bOgQlgcLW83BtlWdC0PES3xU5nEUCiNfXNKSeUT8HJTEsggQ6c17WjMcunZENEWiRqCQNY3ZXzvrqGKrJ/mm9BrRsgaFZMRh5j0eUhT1eJ4pVp6fleTAYIumuagpwG41MR3CG57dImxCoeFAcCDMikJEQKBknmhaDsEa9UFHzl8+hTsroI30ktTK7kOPf4XKbkuNGX+lZZwZPlWkfh/sQLSD59psvJDVvEQTrX1/KQ=='
  },
  bye: { crazy: 'indeed' }
}
JSON valid? true
```

------

## Encryption & Decryption using password

```js
const secretMsg = "This is some secret text";

const envPwd = await signer.encrypt(secretMsg, "somepass1234");
console.log("Envelope (Password):", envPwd);

const decPwd = await signer.decrypt(envPwd, "somepass1234");
console.log("Decrypted (Password):", decPwd);
```

Output:

```sh
Envelope (Password): {
  method: 'password',
  salt: 'QxGLufg1lXn6boTVHme8+Q==',
  iv: 'yum57MIAZc0hUBLXPd7hxQ==',
  tag: 'jok95AmgKTj0okoLrFeL0A==',
  ciphertext: 'cDz+F+z8i9emqTO5COKOYfnYWxTB4spC'
}
Decrypted (Password): This is some secret text
```

