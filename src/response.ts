/*
 * Author    : Francesco
 * Created at: 2023-12-09 17:52
 * Edited by : Francesco
 * Edited at : 2023-12-09 18:03
 *
 * Copyright (c) 2023 Xevolab S.R.L.
 */

import { KeyObject, X509Certificate } from "crypto";

import { RequestObject } from "./query";
import TSA, { hashAlgIdentifier } from ".";

export function getResponse(request: RequestObject, {
	key,
	certs = [],
}: {
	key: KeyObject,
	certs?: X509Certificate[],
}): Buffer {

	return TSA(request.messageImprint.hashedMessage, {
		hashAlgorithm: Object.keys(hashAlgIdentifier).find(k => hashAlgIdentifier[k] === request.messageImprint.hashAlgorithm) || "SHA-256",
		nonce: request.nonce,
		certReq: request.certReq,

		key,
		certs,
	});

};
