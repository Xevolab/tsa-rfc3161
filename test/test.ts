/*
 * Author    : Francesco
 * Created at: 2023-09-24 09:53
 * Edited by : Francesco
 * Edited at : 2024-07-31 19:59
 *
 * Copyright (c) 2023 Xevolab S.R.L.
 */

import { describe, it } from "node:test";
import { expect } from "chai";

import { createHash, createPrivateKey } from "crypto";
import fs from "fs";

import { TimeStampReq, TimeStampResp, parseCerts } from "../src/index";

import { execSync as exec } from "child_process";

const key = createPrivateKey({
	key: fs.readFileSync(__dirname + "/tsa.pem", "ascii"),
	format: "pem",
	type: "pkcs1"
});
const certs = parseCerts(fs.readFileSync(__dirname + "/tsa.chain.crt", "ascii"));

randomFile();
const f = fs.readFileSync(__dirname + "/random.txt", "ascii");

describe("TimeStampReq", () => {

	["SHA256", "SHA384", "SHA512"].forEach((hashAlgorithm: string) => {
		describe("Hash algorithm: " + hashAlgorithm, () => {

			exec(`openssl ts -query -data test/random.txt -sha${hashAlgorithm.slice(-3).toLowerCase()} -cert -out test/random.txt_openssl_${hashAlgorithm}.tsq`);
			console.log(`openssl ts -query -data test/random.txt -sha${hashAlgorithm.slice(-3).toLowerCase()} -cert -out test/random.txt_openssl_${hashAlgorithm}.tsq`);


			// Grabbing nonce from OpenSSL TimeStampReq
			let nonce = exec(`openssl ts -query -in test/random.txt_openssl_${hashAlgorithm}.tsq -text`);
			// @ts-ignore
			nonce = nonce.toString().match(/Nonce: 0x([0-9A-F]+)/)?.[1];
			// @ts-ignore
			nonce = Buffer.from(nonce, "hex");

			describe("create", () => {

				const tsq = new TimeStampReq({
					version: 1,
					messageImprint: {
						hashAlgorithm,
						hashedMessage: createHash(hashAlgorithm.toLowerCase()).update(f).digest()
					},
					certReq: true,
					nonce
				});

				if (!tsq.buffer) return;

				// Save TimeStampReq to file
				fs.writeFileSync(__dirname + `/random.txt.tsq`, tsq.buffer);

				it("should return a TimeStampReq", () => {
					expect(tsq).to.be.instanceOf(TimeStampReq);
				});

				it("should be DER encoded", () => {
					expect(tsq.buffer).to.be.instanceOf(Buffer);
				});

				it("should be a valid TimeStampReq according to OpenSSL", () => {
					expect(exec(`openssl ts -query -in test/random.txt.tsq`)).to.not.be.instanceOf(Error);
				});

				it("should be equal to OpenSSL TimeStampReq", () => {
					expect(tsq.buffer).to.be.deep.equal(fs.readFileSync(__dirname + `/random.txt_openssl_${hashAlgorithm}.tsq`));
				});
			});

			describe("parse", () => {

				const tsq = new TimeStampReq().fromDER(fs.readFileSync(__dirname + `/random.txt_openssl_${hashAlgorithm}.tsq`));

				it("should return a TimeStampReq", () => {
					expect(tsq).to.be.instanceOf(TimeStampReq);
				});

				it("should have certReq", () => {
					expect(tsq.request?.certReq).to.be.true;
				})

				it("should have messageImprint", () => {
					expect(tsq.request?.messageImprint).to.be.not.undefined;
				})

				it("should have the correct messageImprint hashAlgorithm", () => {
					expect(tsq.request?.messageImprint?.hashAlgorithm).to.be.equal(hashAlgorithm);
				})

				it("should have messageImprint hashedMessage", () => {
					expect(tsq.request?.messageImprint?.hashedMessage).to.be.instanceOf(Buffer);
				})

				it("should have the correct messageImprint hashedMessage", () => {
					expect(tsq.request?.messageImprint?.hashedMessage).to.be.deep.equal(createHash(hashAlgorithm.toLowerCase()).update(f).digest());
				})

				it("should have nonce", () => {
					expect(tsq.request?.nonce).to.be.instanceOf(Buffer);
				})

				it("should have the correct nonce", () => {
					if (!tsq.request?.nonce) return;
					if (!nonce) return;

					// @ts-ignore
					expect(tsq.request.nonce).to.be.deep.equal(nonce);
				})

			});
		});
	});


});

describe("TimeStampResp", () => {

	["SHA256", "SHA384", "SHA512"].forEach((hashAlgorithm: string) => {
		describe("Hash algorithm: " + hashAlgorithm, () => {

			exec(`openssl ts -reply -queryfile test/random.txt_openssl_${hashAlgorithm}.tsq -sha${hashAlgorithm.slice(-3).toLowerCase()} -out test/random.txt_openssl_${hashAlgorithm}.tsr -config test/tsa.conf`);
			console.log(`openssl ts -reply -queryfile test/random.txt_openssl_${hashAlgorithm}.tsq -sha${hashAlgorithm.slice(-3).toLowerCase()} -out test/random.txt_openssl_${hashAlgorithm}.tsr -config test/tsa.conf`);

			describe("query from TSQ", () => {

				const req = new TimeStampReq().fromDER(fs.readFileSync(__dirname + `/random.txt_openssl_${hashAlgorithm}.tsq`));

				if (!req.request) throw new Error("Invalid TimeStampReq");

				req.request.reqPolicy = "1.2.3.4.1";

				const tsr = req.sign({ key, certs }, {});

				fs.writeFileSync(__dirname + `/random.txt_${hashAlgorithm}.tsr`, tsr.buffer);

				it("should return a TimeStampResp", () => {
					expect(tsr).to.be.instanceOf(TimeStampResp);
				})

				it("should be a valid TimeStampReq according to OpenSSL", () => {
					expect(exec(`openssl ts -reply -in test/random.txt_${hashAlgorithm}.tsr -text`)).to.not.be.instanceOf(Error);
				})

				/* it("should be equal to OpenSSL TimeStampResp", () => {
					expect(tsr.buffer).to.be.deep.equal(fs.readFileSync(__dirname + `/random.txt_openssl_${hashAlgorithm}.tsr`));
				}); */

			});

		})
	})

});

function randomFile(): void {
	const { randomBytes } = require("crypto");

	const content = randomBytes(32).toString("hex");

	fs.writeFileSync(__dirname + "/random.txt", content);
}

/*(() => {


	chai.should();

	const tsq = new TimeStampReq().fromDER(fs.readFileSync("README_md.tsq"));

	// const tsq = new TimeStampReq({
	// 	"version": 1,
	// 	"messageImprint": {
	// 		"hashAlgorithm": "SHA-512",
	// 		"hashedMessage": Buffer.from("a0faddfbaf1cc2dc375ee3a355288224b12be1dc08d29535585b2951acbccaf5ba8bcd72667ab9d093b818aab34cd6c68f67599ae83c5545325d54cdaea5f602", "hex")
	// 	},
	// 	"reqPolicy": "1.2.3.4.1",
	// 	"nonce": 1234567890,
	// 	"certReq": true
	// });

	const res = tsq.sign({ certs }, { externalSignature: true, signingHashAlgorithm: "SHA384" });

	if (!res.signedDigest) return;

	res.setSignature(customSigner(res.signedDigest, "SHA384"));

	// console.log(res);
	fs.writeFileSync("timestamp.tsr", res.buffer);
})()*/
