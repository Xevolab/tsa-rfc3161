/*
 * Author    : Francesco
 * Created at: 2023-09-24 09:53
 * Edited by : Francesco
 * Edited at : 2023-12-14 15:22
 *
 * Copyright (c) 2023 Xevolab S.R.L.
 */

import { createPrivateKey, privateEncrypt } from "crypto";
import fs from "fs";

/**
 * References:
 * https://stackoverflow.com/questions/43090745/node-js-crypto-sign-a-hash-value
 * https://gist.github.com/mattwildig/33e9e7d6b4561f0db5283afe1a9eeb94
 * https://github.com/golang/go/blob/83843b16100d889bc84580c9427e02c7c9cee769/src/crypto/rsa/pkcs1v15.go#L196-L213
 */

export const customSigner = (hash: Buffer, hashAlgorithm: "SHA256" | "SHA384" | "SHA512") => {
	const key = createPrivateKey({
		key: fs.readFileSync("tsa.pem", "ascii"),
		format: "pem",
		type: "pkcs1"
	});

	const asnPrefix = {
		SHA256: Buffer.from([0x30, 0x31, 0x30, 0x0d, 0x06, 0x09, 0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x01, 0x05, 0x00, 0x04, 0x20]),
		SHA384: Buffer.from([0x30, 0x41, 0x30, 0x0d, 0x06, 0x09, 0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x02, 0x05, 0x00, 0x04, 0x30]),
		SHA512: Buffer.from([0x30, 0x51, 0x30, 0x0d, 0x06, 0x09, 0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x03, 0x05, 0x00, 0x04, 0x40]),
	}

	var encoded = Buffer.concat([asnPrefix[hashAlgorithm], hash]);
	const newSignature = privateEncrypt(key, encoded);

	return newSignature;
}
