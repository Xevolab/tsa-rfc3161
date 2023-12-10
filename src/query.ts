/*
 * Author    : Francesco
 * Created at: 2023-12-09 17:52
 * Edited by : Francesco
 * Edited at : 2023-12-09 18:03
 *
 * Copyright (c) 2023 Xevolab S.R.L.
 */

import * as asn1js from "asn1js";
import { KeyObject, X509Certificate } from "crypto";

import { parseOID } from "./parseOID";
import { getResponse } from "./response";

/** */
export function generateQuery(
	hashedMessage: string | Buffer, {
		hashAlgorithm,
		nonce,
	}: {
		hashAlgorithm: string,
		nonce?: number,
	}): Buffer {
	return Buffer.from("");
}

export type RequestObject = {
	version: number,
	messageImprint: {
		hashAlgorithm: string,
		hashedMessage: Buffer,
	},
	reqPolicy?: string | null,
	nonce?: Buffer | undefined,
	certReq?: boolean,
	extensions?: any[] | null,
};

/**
 * Parse the request query
 * @param request    TimeStampReq
 *
 * @returns				TimeStampResp
*/
export function parseQuery(request: Buffer): RequestObject {

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

	return {
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

};

export class TimeStampReq {

	originalRequest: Buffer;
	request: RequestObject;

	constructor(request: Buffer) {
		this.originalRequest = request;
		this.request = parseQuery(request);
	}

	getVersion(): number {
		return this.request.version;
	}

	sign(params: {
		key: KeyObject,
		certs?: X509Certificate[],
	}): Buffer {
		return getResponse(this.request, params);
	}

};
