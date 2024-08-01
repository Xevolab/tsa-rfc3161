/*
 * Author    : Francesco
 * Created at: 2024-07-31 19:51
 * Edited by : Francesco
 * Edited at : 2024-07-31 19:56
 *
 * Copyright (c) 2024 Xevolab S.R.L.
 */

import {
	createHash, KeyObject, SignKeyObjectInput, X509Certificate,
} from "crypto";

import * as asn1js from "asn1js";

export function keyForAlg(key: KeyObject): KeyObject | SignKeyObjectInput {
	if (key.asymmetricKeyType === "rsa") return key;
	if (key.asymmetricKeyType === "ec") return { dsaEncoding: "ieee-p1363", key };

	throw new TypeError(`key is is not supported`);
}

export function getSignedAttributes(
	messageHash: Buffer,
	signingTime: Date,
	certs: X509Certificate[] = [],
) {
	return [
		// contentType
		new asn1js.Sequence({
			value: [
				new asn1js.ObjectIdentifier({
					value: "1.2.840.113549.1.9.3",
				}),
				new asn1js.Set({
					value: [
						new asn1js.ObjectIdentifier({
							value: "1.2.840.113549.1.9.16.1.4", // id-ct-TSTInfo
						}),
					],
				}),
			],
		}),

		// signingTime
		new asn1js.Sequence({
			value: [
				new asn1js.ObjectIdentifier({
					value: "1.2.840.113549.1.9.5",
				}),
				new asn1js.Set({
					value: [
						new asn1js.UTCTime({ valueDate: signingTime }),
					],
				}),
			],
		}),

		// messageDigest
		new asn1js.Sequence({
			value: [
				new asn1js.ObjectIdentifier({
					value: "1.2.840.113549.1.9.4",
				}),
				new asn1js.Set({
					value: [
						new asn1js.OctetString({ valueHex: messageHash }),
					],
				}),
			],
		}),

		// signingCertificateV2
		// https://www.rfc-editor.org/rfc/rfc2634.html#section-5.4.1
		/*
			Attribute ::= SEQUENCE {
				attrType OBJECT IDENTIFIER,
				attrValues SET OF AttributeValue
			}
		*/
		// NOTE: this is what would need to be created different in v1 or v2
		//       v1 does not support ESSCertIDv2
		new asn1js.Sequence({
			value: [
				new asn1js.ObjectIdentifier({
					value: "1.2.840.113549.1.9.16.2.47",
				}),
				new asn1js.Set({
					value: [
						/*
							SigningCertificateV2 ::=  SEQUENCE {
								certs        SEQUENCE OF ESSCertIDv2,
								policies     SEQUENCE OF PolicyInformation OPTIONAL
							}
						*/
						new asn1js.Sequence({
							value: [
								new asn1js.Sequence({
									value: [
										/*
											ESSCertIDv2 ::=  SEQUENCE {
												hashAlgorithm           AlgorithmIdentifier
														DEFAULT {algorithm id-sha256},
												certHash                 Hash,
												issuerSerial             IssuerSerial OPTIONAL
											}
										*/
										new asn1js.Sequence({
											value: [
												new asn1js.OctetString({
													valueHex: Buffer.from(createHash("sha256").update(certs[0].raw).digest("hex"), "hex"),
												}),
											],
										}),
									],
								}),
							],
						}),
					],
				}),
			],
		}),
	];
}

export function getCertificateIssuerASNSequence(cert: X509Certificate): unknown {
	return asn1js.fromBER(cert.raw).result.valueBlock.value[0].valueBlock.value[3].valueBlock.value;
}
export function getCertificateSubjectASNSequence(cert: X509Certificate): unknown {
	return asn1js.fromBER(cert.raw).result.valueBlock.value[0].valueBlock.value[5].valueBlock.value;
}
