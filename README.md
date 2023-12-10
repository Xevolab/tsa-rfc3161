# Timestamping Authority
RFC 3161 Timestamping Authority implementation in Node.js

## Introduction

This repository contains a Node.js implementation of a Timestamping Authority (TSA) as defined in [RFC 3161](https://tools.ietf.org/html/rfc3161). The implementation is based on the [Node.js crypto module](https://nodejs.org/api/crypto.html) and the [ASN.1 JavaScript decoder](https://npmjs.com/package/asn1.js).

## Installation

In order to install the library, run the following command:

```bash
npm install @xevolab/timestamp-token
```

You will be able to import the library using the following syntax:

```javascript
const {TimeStampReq, TimeStampResp} = require("@xevolab/timestamp-token");
// or
import {TimeStampReq, TimeStampResp} from "@xevolab/timestamp-token";
```

# Usage

## TimeStampReq

### Importing a TimeStampReq from a DER-encoded buffer

A TimeStampReq can be imported from a DER-encoded buffer using the `TimeStampReq.fromDER` method:

```javascript
import {TimeStampReq} from "@xevolab/timestamp-token";

const tsq = new TimeStampReq().fromDER(buffer);
```

This method returns a `TimeStampReq` object.

### Generating a TimeStampReq with a JSON object

A TimeStampReq can be generated using a more convenient JSON object using the `TimeStampReq` constructor:

```javascript
import {TimeStampReq} from "@xevolab/timestamp-token";

const tsq = new TimeStampReq({
   version: 1,
   messageImprint: {
      hashAlgorithm: "sha256",
      hashedMessage: "012ABCDEF..."|Buffer
   },
   policy: "",    // optional
   nonce: 0,      // optional
   certReq: false // optional
});
```

The `TimeStampReq` constructor returns a `TimeStampReq` object. The `buffer` property of the `TimeStampReq` object contains the DER-encoded request.

## TimeStampResp

### Creating a response from a TimeStampReq

A TimeStampResp is generated and signed using the `TimeStampReq.sign` method:

```javascript
import {TimeStampReq, TimeStampResp} from "@xevolab/timestamp-token";

const tsq = new TimeStampReq().fromDER(buffer);
const tsr = tsq.sign({
   // The private key used to sign the response
   key: KeyObject,
   // Array of X509Certificate objects where the first one is the signer certificate
   certs: X509Certificate[],
});
```

The `sign` method returns an instance of `TimeStampResp`.

### Creating a response without a TimeStampReq

A TimeStampResp can be created without a TimeStampReq using the `TimeStampResp` constructor:

```javascript
import {TimeStampResp} from "@xevolab/timestamp-token";

const resp = new TimeStampResp(
   hashedMessage: string | Buffer,
   {
      // Hash algorithm used to hash the message
      hashAlgorithm: "SHA256"|"SHA384"|"SHA512",

      nonce: number | Buffer, // optional
      certReq: boolean,       // optional

      key: KeyObject,
      certs: X509Certificate[],

      // Additional optional parameters for the signing process
      signingOptions: {
         // Signing options
         signingHashAlgorithm: "SHA256"|"SHA384"|"SHA512",
      }
   }
);
```

The `TimeStampResp` constructor returns an instance of `TimeStampResp`.
The `buffer` property of the `TimeStampResp` object contains the DER-encoded response.

# OpenSSL

OpenSSL has a built-in implementation of a TSA. The following commands can be used to generate a TimeStampReq and a TimeStampResp.

For help setting up the OpenSSL config for TSA you can refer to [“Setting up a Time Stamping Authority with OpenSSL” (jimby.name)](https://www.jimby.name/techbits/recent/openssl_tsa/).

## Generating a TimeStampReq

The OpenSSL command line tool can be used to generate a TimeStampReq for a generic file using the following command:

```bash
openssl ts -query -data <file> [-no_nonce] [-sha256|sha384|sha512] [-cert] > file.tsq
```
Where:

- `<file>` is the path to the file to be timestamped
- `-no_nonce` disables the nonce value
- `-sha256` uses SHA-256 as the hash algorithm, `-sha384` uses SHA-384 and `-sha512` uses SHA-512
- `-cert` enables the inclusion of the certificate chain in the request (`certReq` flag is on)

You can preview the content of the DER buffer using the following command:

```bash
openssl ts -reply -in file.tsq -text
```

## Generating a TimeStampResp

The OpenSSL command line tool can be used to generate a TimeStampResp for a generic TimeStampReq using the following command:

```bash
openssl ts -reply -queryfile <file.tsq> -inkey <private-key.pem> -signer <certificate.pem> -CAfile <certificate.pem> -out file.tsr
```

Where:
- `<file.tsq>` is the path to the TimeStampReq file
- `<private-key.pem>` is the path to the private key used to sign the response
- `<certificate.pem>` is the path to the certificate used to sign the response
- `-CAfile <certificate.pem>` is the path to the certificate chain used to sign the response
- `file.tsr` is the path where the TimeStampResp will be saved

You can preview the content of the DER buffer using the following command:

```bash
openssl ts -reply -in file.tsr -text
```

## Verifying a TimeStampResp

```bash
openssl ts -verify -queryfile file.tsq -in file.tsr -CAfile <certificate.pem>
```

Where:
- `<file.tsq>` is the path to the TimeStampReq file
- `<file.tsr>` is the path to the TimeStampResp file
- `<certificate.pem>` is the path to the certificate chain used to sign the response

# Example

```javascript
import {TimeStampReq, TimeStampResp, parseCerts} from "@xevolab/timestamp-token";
import { createPrivateKey } from "crypto";
import fs from "fs";

const key = createPrivateKey({
   key: fs.readFileSync("private.key.pem", "ascii"),
   format: "pem",
   type: "pkcs1"
});
const certs = parseCerts(fs.readFileSync("cert.chain.crt", "ascii"));

// ---
// From a DER buffer

const tsq = new TimeStampReq().fromDER(fs.readFileSync("file.tsq"));

const tsr = tsq.sign({
   key,
   certs,
});

const tsrBuffer = tsr.buffer;

// ---
// From a JSON object

const tsr2 = new TimeStampResp("42191cda4fea645078d6e14e311dfa4bbd04f154fbbe9376e8a3833242cd5c03", {
   hashAlgorithm: "SHA256",
   key,
   certs
});

const tsr2Buffer = tsr2.buffer;
```
