/*
 * Author    : Francesco
 * Created at: 2023-12-09 17:52
 * Edited by : Francesco
 * Edited at : 2023-12-13 20:20
 *
 * Copyright (c) 2023 Xevolab S.R.L.
 */

import * as asn1js from "asn1js";
import { KeyObject, X509Certificate } from "crypto";

import { hashAlgIdentifier, hashAlgOID, parseOID } from "./parseOID";
import { TimeStampResp, SignOptions } from "./response";

export type RequestObject = {
	version: number,
	messageImprint: {
		hashAlgorithm: string,
		hashedMessage: Buffer,
	},
	reqPolicy?: string | null,
	nonce?: Buffer | number | undefined,
	certReq?: boolean,
	// extensions?: any[] | null,
};

export class TimeStampReq {

	public buffer?: Buffer;
	public request?: RequestObject;

	/**
	 * Creates an instance of TimeStampReq from a request object (nicely formatted)
	 *
	 * @param   {RequestObject}  request
	 */
	constructor(request?: RequestObject) {
		if (!request) return;

		this.request = request;

		// Validating the request object
		if (request.version !== 1) throw new Error("Invalid request; version must be 1.");

		if (!request.messageImprint) throw new Error("Invalid request; messageImprint is required.");
		if (!request.messageImprint.hashAlgorithm) throw new Error("Invalid request; messageImprint.hashAlgorithm is required.");
		request.messageImprint.hashAlgorithm = request.messageImprint.hashAlgorithm.toUpperCase().replaceAll("-", "");
		const hashAlgs = ["SHA256", "SHA384", "SHA512"];
		if (!hashAlgs.includes(request.messageImprint.hashAlgorithm)) throw new Error("Invalid hashAlgorithm; needs to be one of " + hashAlgs.join(", ") + ".");
		if (!request.messageImprint.hashedMessage) throw new Error("Invalid request; messageImprint.hashedMessage is required.");
		if (!Buffer.isBuffer(request.messageImprint.hashedMessage)) throw new Error("Invalid request; messageImprint.hashedMessage needs to be a valid buffer.");

		// request.reqPolicy is optional but if present it needs to be a valid OID
		if (request.reqPolicy && !request.reqPolicy.match(/^[0-9]+(\.[0-9]+)+$/)) throw new Error("Invalid request; reqPolicy needs to be a valid OID.");

		// request.nonce is optional but if present it needs to be a valid buffer or a number
		if (request.nonce) {
			if (typeof request.nonce === "number") request.nonce = Buffer.from(request.nonce.toString(16), "hex");
			if (!Buffer.isBuffer(request.nonce))
				throw new Error("Invalid request; nonce needs to be a valid buffer or number.");
		}

		// request.certReq is optional but if present it needs to be a boolean
		if (request.certReq && typeof request.certReq !== "boolean") throw new Error("Invalid request; certReq needs to be a boolean.");

		// Generate the DER encoded request
		this.buffer = Buffer.from(new asn1js.Sequence({
			value: [
				new asn1js.Integer({ value: request.version }),
				new asn1js.Sequence({
					value: [
						new asn1js.Sequence({
							value: [
								new asn1js.ObjectIdentifier({ value: hashAlgOID[request.messageImprint.hashAlgorithm] }),
								new asn1js.Null(),
							],
						}),
						new asn1js.OctetString({ valueHex: request.messageImprint.hashedMessage }),
					],
				}),
				...(request.reqPolicy ? [new asn1js.ObjectIdentifier({ value: request.reqPolicy })] : []),
				// @ts-ignore
				...(request.nonce ? [new asn1js.Integer({ valueHex: request.nonce })] : []),
				...(request.certReq ? [new asn1js.Boolean({ value: request.certReq })] : []),
				// ...(request.extensions ? [new asn1js.Sequence({ value: request.extensions })] : []),
			]
		}).toBER(false));

	}

	/**
	 * Creates an instance of TimeStampReq from a DER encoded request generated somewhere else
	 *
	 * @param   {Buffer}  request  A buffer containing the DER encoded request
	 *
	 * @return  {TimeStampReq}     The instance of TimeStampReq
	 */
	fromDER(request: Buffer): TimeStampReq {
		this.buffer = request;

		// Parse request from BER
		const r = asn1js.fromBER(request);
		if (r.offset === (-1)) throw new Error("Invalid request; needs to be a valid BER.");

		/**
		 * TimeStampReq ::= SEQUENCE  {
		 *  version                      INTEGER  { v1(1) },
		 *  messageImprint               MessageImprint,
		 *   --a hash algorithm OID and the hash value of the data to be
		 *   --time-stamped
		 *   reqPolicy             TSAPolicyId              OPTIONAL,
		 *   nonce                 INTEGER                  OPTIONAL,
		 *   certReq               BOOLEAN                  DEFAULT FALSE,
		 *   extensions            [0] IMPLICIT Extensions  OPTIONAL
		 * }
		 *
		 * MessageImprint ::= SEQUENCE  {
		 *   hashAlgorithm                AlgorithmIdentifier,
		 *   hashedMessage                OCTET STRING
		 * }
		 */
		let i = 2;

		this.request = {
			// @ts-ignore
			version: r.result.valueBlock.value[0].valueBlock._valueDec,
			// @ts-ignore
			messageImprint: {
				// @ts-ignore
				// Parse OID from BER
				hashAlgorithm: parseOID(r.result.valueBlock.value[1].valueBlock.value[0].valueBlock.value[0].valueBlock.value.map((i: any) => i.valueDec)),
				// @ts-ignore
				hashedMessage: Buffer.from(r.result.valueBlock.value[1].valueBlock.value[1].valueBlock.valueHexView),
			},
			// @ts-ignore
			reqPolicy: r.result.valueBlock.value[2].idBlock.tagNumber === 6 ? parseOID(r.result.valueBlock.value[i++].valueBeforeDecodeView) : null,
			// @ts-ignore
			nonce: r.result.valueBlock.value[i]?.idBlock.tagNumber === 2 ? Buffer.from(r.result.valueBlock.value[i++].valueBlock.valueHexView) : undefined,
			// @ts-ignore
			certReq: r.result.valueBlock.value[i]?.idBlock.tagNumber === 1 ? r.result.valueBlock.value[i++].valueBlock.value : false,
			// @ts-ignore
			extensions: r.result.valueBlock.value[i]?.idBlock.tagCLass === 0 && r.result.valueBlock.value[i].idBlock.tagNumber === 0 ? r.result.valueBlock.value[i++].valueBlock.value : null,
		};

		// Convert hashAlgorithm from OID to identifier
		if (this.request && this.request.messageImprint)
			this.request.messageImprint.hashAlgorithm = hashAlgIdentifier[this.request.messageImprint.hashAlgorithm];

		return this;
	}

	sign(params: {
		key?: KeyObject,
		certs?: X509Certificate[],
	}, signingOptions?: SignOptions): TimeStampResp {
		if (!this.request) throw new Error("Request not initialized.");

		return new TimeStampResp(this.request.messageImprint.hashedMessage, {
			hashAlgorithm: this.request.messageImprint.hashAlgorithm,
			nonce: this.request.nonce,
			certReq: this.request.certReq,

			key: params.key || undefined,
			certs: params.certs,

			signingOptions
		});
	}

};
