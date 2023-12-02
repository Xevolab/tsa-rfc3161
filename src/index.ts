/*
 * Author    : Francesco
 * Created at: 2023-12-01 11:22
 * Edited by : Francesco
 * Edited at : 2023-12-02 14:49
 *
 * Copyright (c) 2023 Xevolab S.R.L.
 */

/**
 * Some comments contain content taken from RFC 3161, RFC 5816 and RFC 2630.
 */

import { KeyObject, SignKeyObjectInput, X509Certificate, sign, randomBytes, createHash } from "crypto";
import * as asn1js from "asn1js";

export function parseCerts(certs: string): X509Certificate[] {
	return certs.split("-----END CERTIFICATE-----").filter((j: string) => j.trim() !== "").map((j: string) => new X509Certificate(`${j}-----END CERTIFICATE-----`));
}

/**
 * Generate a timestamp token from a payload
 *
 * @return  {string}  JWT token that rappresent the timestamped
 */
export default function TSA(
	{
		version = 2,
		messageImprint: {
			hashAlgorithm = "",
			hashedMessage = ""
		},
		nonce
	}: {
		version?: number,
		messageImprint: {
			hashAlgorithm: string,
			hashedMessage: string
		},
		nonce?: number,
	},
	{
		key,
		certs = [],

		tsaName = "",
	}: {
		key: KeyObject,

		certs?: X509Certificate[],

		tsaName?: string,
	}
): TSAResponse {

	// --> Validating payload

	if (version && version !== 2) throw new Error("Invalid version; needs to be 2.");

	/**
	 * hashAlgorithm must be a string that rappresent the hash algorithm used to hash the message
	 * Valid values are: SHA-256, SHA-384, SHA-512
	 */
	if (typeof hashAlgorithm !== "string") throw new Error("Invalid hashAlgorithm; needs to be a string.");
	const hashAlgs = ["SHA-256", "SHA-384", "SHA-512"];
	if (!hashAlgs.includes(hashAlgorithm)) throw new Error("Invalid hashAlgorithm; needs to be one of " + hashAlgs.join(", ") + ".");

	/**
	 * hashedMessage must be a base64url string that rappresent the hashed message
	 */
	if (typeof hashedMessage !== "string") throw new Error("Invalid hashedMessage; needs to be a string.");

	/**
	 * TSTInfo ::= SEQUENCE  {
	 *   version                      INTEGER  { v1(1) },
	 *   policy                       TSAPolicyId,
	 *   messageImprint               MessageImprint,
	 *     -- MUST have the same value as the similar field in
	 *     -- TimeStampReq
	 *   serialNumber                 INTEGER,
	 *    -- Time-Stamping users MUST be ready to accommodate integers
	 *    -- up to 160 bits.
	 *   genTime                      GeneralizedTime,
	 *   accuracy                     Accuracy                 OPTIONAL,
	 *   ordering                     BOOLEAN             DEFAULT FALSE,
	 *   nonce                        INTEGER                  OPTIONAL,
	 *     -- MUST be present if the similar field was present
	 *     -- in TimeStampReq.  In that case it MUST have the same value.
	 *   tsa                          [0] GeneralName          OPTIONAL,
	 *   extensions                   [1] IMPLICIT Extensions   OPTIONAL
	 * }
	 */
	const payload = new asn1js.Sequence({
		value: [
			// version
			new asn1js.Integer({ value: 1 }),

			/**
			 * TSAPolicyId ::= OBJECT IDENTIFIER
			 * OMITTED (not supported)
			 */
			new asn1js.ObjectIdentifier({ value: "1.2.3.4.1" }),

			/**
			 * MessageImprint ::= SEQUENCE  {
			 *   hashAlgorithm                AlgorithmIdentifier,
			 *   hashedMessage                OCTET STRING  }
			 */
			new asn1js.Sequence({
				value: [
					// hashAlgorithm
					new asn1js.Sequence({
						value: [
							new asn1js.ObjectIdentifier({
								value: hashAlgIdentifier[hashAlgorithm]
							}),
							new asn1js.Null()
						]
					}),
					// hashedMessage
					new asn1js.OctetString({ valueHex: Buffer.from(hashedMessage, "hex") })
				]
			}),

			/**
			 * CertificateSerialNumber ::= INTEGER
			 */
			new asn1js.Integer({ valueHex: Buffer.from(certs[0].serialNumber, "hex") }),

			/**
			 * GeneralizedTime ::= CHOICE {
			 *   utcTime        UTCTime,
			 *   generalTime    GeneralizedTime
			 * }
			 */
			new asn1js.GeneralizedTime({ valueDate: new Date() }),

			/**
			 * Accuracy ::= SEQUENCE {
			 *   seconds        INTEGER           OPTIONAL,
			 *   millis     [0] INTEGER  (1..999) OPTIONAL,
			 *   micros     [1] INTEGER  (1..999) OPTIONAL
			 * }
			 * OMITTED (not supported)
			 */
			// new asn1js.Sequence({
			// 	value: [
			// 		new asn1js.Integer({ value: 0 }),
			// 		new asn1js.Integer({ value: 0, idBlock: { tagClass: 0, tagNumber: 0 } }),
			// 		new asn1js.Integer({ value: 0, idBlock: { tagClass: 0, tagNumber: 1 } })
			// 	]
			// }),

			/**
			 * ordering BOOLEAN DEFAULT FALSE,
			 * Resolved to false
			 */
			new asn1js.Boolean({ value: false }),

			/**
			 * nonce INTEGER OPTIONAL,
			 * If present in request, otherwise omitted
			 */
			// ...(nonce ? [new asn1js.Integer({ value: nonce })] : []),

			/**
			 * tsa [0] GeneralName OPTIONAL,
			 * If present, it must be one of the subject names included in the certificate that is to
			 * be used to verify the token.
			 */
			new asn1js.Constructed({
				// Apply [0] tag
				idBlock: { tagClass: 3, tagNumber: 0 },

				value: [
					new asn1js.Constructed({
						// Apply [4] tag
						idBlock: { tagClass: 3, tagNumber: 4 },

						value: [new asn1js.Sequence({
							value: getCertificateSubjectASNSequence(certs[0])
						})]
					})
				]
			}),
		]
	});

	const messageDigest = createHash("SHA-512").update(Buffer.from(payload.toBER(false))).digest("hex");

	/**
	 * If present, nonce must be a number
	 */
	if (nonce && typeof nonce !== "number") throw new Error("Invalid nonce; needs to be a number.");

	// --> Loading the key(s)

	if (!key || !(key instanceof KeyObject)) throw new Error("Invalid key; needs to be a KeyObject.");

	// --> Loading the certificates

	if (!Array.isArray(certs)) throw new Error("Invalid certs; needs to be an array.");
	if (certs.length === 0) throw new Error("Invalid certs; needs to be an array with at least one element.");

	// --> Generating the signature

	// The signature is generated using the private key of the TSA, by signing the DER encoded
	// payload and, if present, the signed attributes.
	const signature = sign("SHA512", Buffer.from(getSignedAttributes(messageDigest).toBER(false)), keyForAlg(key));

	/**
	 * TimeStampResp ::= SEQUENCE  {
	 *   status                  PKIStatusInfo,
	 *   timeStampToken          TimeStampToken     OPTIONAL
	 * }
	 */

	const TimeStampResp = new asn1js.Sequence();

	/**
	 * PKIStatusInfo ::= SEQUENCE {
	 *   status        PKIStatus,
	 *   statusString  PKIFreeText     OPTIONAL,
	 *   failInfo      PKIFailureInfo  OPTIONAL
	 * }
	 *
	 * PKIStatus ::= INTEGER {
	 *   granted                (0),
	 *   ... (See RFC 3161)
	 * }
	 *
	 * PKIFreeText ::= SEQUENCE SIZE (1..MAX) OF UTF8String
	 *
	 * PKIFailureInfo ::= BIT STRING {
	 *   badAlg               (0),
	 *   ... (See RFC 3161)
	 * }
	 */
	TimeStampResp.valueBlock.value.push(new asn1js.Sequence({
		value: [
			// status
			new asn1js.Integer({ value: 0 }),
			// statusString
			// new asn1js.Sequence({ value: [new asn1js.Utf8String({ value: "Granted" })] }),
			// failInfo
			// new asn1js.BitString({ valueHex: new ArrayBuffer(1) }),
		]
	})); // status

	/**
	 * TimeStampToken ::= ContentInfo
	 *   -- contentType is id-signedData
	 *   -- content is SignedData
	 */
	TimeStampResp.valueBlock.value.push(new asn1js.Sequence({
		value: [
			/**
			 * id-signedData OBJECT IDENTIFIER ::= { iso(1) member-body(2) us(840) rsadsi(113549) pkcs(1) pkcs7(7) 2 }
			 */
			new asn1js.ObjectIdentifier({ value: "1.2.840.113549.1.7.2" }), // signedData

			/**
			 * SignedData ::= SEQUENCE {
			 *   version CMSVersion,
			 *   digestAlgorithms DigestAlgorithmIdentifiers,
			 *   encapContentInfo EncapsulatedContentInfo,
			 *   certificates [0] IMPLICIT CertificateSet OPTIONAL,
			 *   crls [1] IMPLICIT RevocationInfoChoices OPTIONAL,
			 *   signerInfos SignerInfos
			 * }
			 */
			new asn1js.Constructed({
				// Apply [0] IMPLICIT tag
				idBlock: { tagClass: 3, tagNumber: 0 },

				value: [new asn1js.Sequence({
					value: [
						/**
						 * CMSVersion ::= INTEGER
						 */
						new asn1js.Integer({ value: 3 }),

						/**
						 * DigestAlgorithmIdentifiers ::= SET OF DigestAlgorithmIdentifier
						 *
						 * DigestAlgorithmIdentifier ::= AlgorithmIdentifier
						 */
						new asn1js.Set({
							value: [

								/**
								 * AlgorithmIdentifier ::= SEQUENCE {
								 *   algorithm OBJECT IDENTIFIER,
								 *   parameters ANY DEFINED BY algorithm OPTIONAL
								 * }
								 */
								new asn1js.Sequence({
									value: [
										new asn1js.ObjectIdentifier({
											value: hashAlgIdentifier[hashAlgorithm]
										}),
										new asn1js.Null()
									]
								}),
							]
						}),


						/**
						 * EncapsulatedContentInfo ::= SEQUENCE {
						 *   eContentType ContentType,
						 *   eContent [0] EXPLICIT OCTET STRING OPTIONAL
						 * }
						 *
						 * eContentType ::= OBJECT IDENTIFIER
						 * eContentType is an object identifier that uniquely specifies the content type.
						 *  For a time-stamp token it is defined as:
						 *  id-ct-TSTInfo  OBJECT IDENTIFIER ::= { iso(1) member-body(2) us(840) rsadsi(113549) pkcs(1) pkcs-9(9) smime(16) ct(1) 4}
						 *
						 * eContent is the content itself, carried as an octet string.
						 * The eContent SHALL be the DER-encoded value of TSTInfo.
						 *
						 */
						new asn1js.Sequence({
							value: [
								/**
								 * ContentType ::= OBJECT IDENTIFIER
								 */
								new asn1js.ObjectIdentifier({ value: "1.2.840.113549.1.9.16.1.4" }), // id-ct-TSTInfo

								/**
								 * EXPLICIT OCTET STRING
								 */
								new asn1js.Constructed({
									// Apply [0] EXPLICIT tag
									idBlock: { tagClass: 3, tagNumber: 0 },

									value: [new asn1js.OctetString({ valueHex: Buffer.from(payload.toBER(false)) })]
								})
							]
						}),

						/**
						 * CertificateSet ::= SET OF CertificateChoices
						 *
						 * CertificateChoices ::= CHOICE {
						 *   certificate Certificate,
						 *   extendedCertificate [0] IMPLICIT ExtendedCertificate,  -- Obsolete
						 *   v1AttrCert [1] IMPLICIT AttributeCertificateV1,        -- Obsolete
						 *   v2AttrCert [2] IMPLICIT AttributeCertificateV2,
						 *   other [3] IMPLICIT OtherCertificateFormat
						 * }
						 *
						 * Certificate ::= SIGNED{TBSCertificate}
						*/
						new asn1js.Constructed({
							idBlock: { tagClass: 3, tagNumber: 0 },
							// @ts-ignore
							value: certs.map(c => new asn1js.Sequence({
								// @ts-ignore
								value: asn1js.fromBER(c.raw).result.valueBlock.value
							}))
						}),

						/**
						 * RevocationInfoChoices ::= SET OF RevocationInfoChoice
						 *
						 * RevocationInfoChoice ::= CHOICE {
						 *   crl CertificateList,
						 *   other [1] IMPLICIT OtherRevocationInfoFormat
						 * }
						 *
						 * CertificateList ::= SIGNED{TBSCertList}
						 *
						 * OMITTED (not supported)
						 */
						// new asn1js.Null(),

						/**
						 * SignerInfos ::= SET OF SignerInfo
						 * SignerInfo ::= SEQUENCE {
						 *   version CMSVersion,
						 *   sid SignerIdentifier,
						 *   digestAlgorithm DigestAlgorithmIdentifier,
						 *   signedAttrs [0] IMPLICIT SignedAttributes OPTIONAL,
						 *   signatureAlgorithm SignatureAlgorithmIdentifier,
						 *   signature SignatureValue,
						 *   unsignedAttrs [1] IMPLICIT UnsignedAttributes OPTIONAL
						 * }
						 */
						new asn1js.Set({
							name: "signerInfos",
							value: [
								new asn1js.Sequence({
									value: [
										/**
										 * CMSVersion ::= INTEGER { v1(1), v2(2) }
										 * v1 -> issuerAndSerialNumber
										 * v3 -> subjectKeyIdentifier
										 */
										new asn1js.Integer({ value: 3 }),

										/**
										 * SignerIdentifier ::= CHOICE {
										 *   issuerAndSerialNumber IssuerAndSerialNumber,
										 *   subjectKeyIdentifier [0] SubjectKeyIdentifier
										 * }
										 *
										 * IssuerAndSerialNumber ::= SEQUENCE {
										 *   issuer Name,
										 *   serialNumber CertificateSerialNumber
										 * }
										 * Name ::= CHOICE { -- only one possibility for now --
										 *  rdnSequence  RDNSequence }
										 *
										 * RDNSequence ::= SEQUENCE OF RelativeDistinguishedName
										 * RelativeDistinguishedName ::=
										 *  SET SIZE (1..MAX) OF AttributeTypeAndValue
										 *
										 * AttributeTypeAndValue ::= SEQUENCE {
										 *   type     AttributeType,
										 *   value    AttributeValue }
										 *
										 * AttributeType ::= OBJECT IDENTIFIER
										 * AttributeValue ::= ANY -- DEFINED BY AttributeType
										 *
										 *
										 * SubjectKeyIdentifier ::= OCTET STRING
										 */
										new asn1js.Sequence({
											value: [
												// issuer
												// @ts-ignore
												new asn1js.Sequence({ value: getCertificateIssuerASNSequence(certs[0]) }),
												// serialNumber
												new asn1js.Integer({ valueHex: Buffer.from(certs[0].serialNumber, "hex") })
											]
										}),

										/**
										 * DigestAlgorithmIdentifier ::= AlgorithmIdentifier
										 */
										new asn1js.Sequence({
											value: [
												new asn1js.ObjectIdentifier({
													value: hashAlgIdentifier["SHA-512"]
												}),
												new asn1js.Null()
											]
										}),

										/**
										 * SignedAttributes ::= SET SIZE (1..MAX) OF Attribute
										 *
										 * Attribute ::= SEQUENCE {
										 *   attrType OBJECT IDENTIFIER,
										 *   attrValues SET OF AttributeValue }
										 *
										 * AttributeValue ::= ANY -- DEFINED BY AttributeType
										 */
										getSignedAttributes(messageDigest),

										/**
										 * SignatureAlgorithmIdentifier ::= AlgorithmIdentifier
										 */
										new asn1js.Sequence({
											value: [
												new asn1js.ObjectIdentifier({
													value: "1.2.840.113549.1.1.1"
												}),
												new asn1js.Null()
											]
										}),

										/**
										 * SignatureValue ::= OCTET STRING
										 */
										new asn1js.OctetString({
											valueHex: signature.buffer
										}),

									]
								})
							]
						})
					]
				})
				]
			})]
	}));

	console.log(Buffer.from(TimeStampResp.toBER(false)).toString("hex"));

	return {
		status: {
			status: 0,
			statusString: "Granted",
		},
		timeStampToken: {
			version: 2,
			policy: "",
			messageImprint: {
				hashAlgorithm,
				hashedMessage
			},
			serialNumber: randomBytes(16).toString("hex"),
			genTime: (new Date()).toISOString().replace(/\..+/, ""),
			nonce: nonce || undefined,
			accuracy: {
				micros: 0,
				millis: 0,
				seconds: 0
			},
			ordering: false,
			extensions: [],
			tsa: "",
		},
		token: Buffer.from(TimeStampResp.toBER(false)).toString("hex")
	};
}

export type TSAResponse = {
	status: {
		status: number,
		statusString?: string,
		failInfo?: string
	},
	timeStampToken: {
		version: number,
		messageImprint: {
			hashAlgorithm: string,
			hashedMessage: string
		},
		serialNumber: string,
		genTime: string,
		nonce?: number,
		accuracy?: {
			micros: number,
			millis: number,
			seconds: number
		},
		ordering: boolean,
		policy: string,
		extensions?: any[],
		tsa?: string,
	},
	token: string
}

function keyForAlg(key: KeyObject): KeyObject | SignKeyObjectInput {

	if (key.asymmetricKeyType === 'rsa')
		return key;
	else if (key.asymmetricKeyType === 'ec')
		return { dsaEncoding: 'ieee-p1363', key };

	throw new TypeError(`key is is not supported`);
}

const hashAlgIdentifier: any = {
	"SHA-256": "2.16.840.1.101.3.4.2.1",
	"SHA-384": "2.16.840.1.101.3.4.2.2",
	"SHA-512": "2.16.840.1.101.3.4.2.3"
}

function getSignedAttributes(messageHash: string) {
	return new asn1js.Constructed({
		idBlock: { tagClass: 3, tagNumber: 0 },
		value: [
			// contentType
			new asn1js.Sequence({
				value: [
					new asn1js.ObjectIdentifier({
						value: "1.2.840.113549.1.9.3"
					}),
					new asn1js.Set({
						value: [
							new asn1js.ObjectIdentifier({
								value: "1.2.840.113549.1.9.16.1.4" // id-ct-TSTInfo
							}),
						]
					})
				]
			}),

			// signingTime
			new asn1js.Sequence({
				value: [
					new asn1js.ObjectIdentifier({
						value: "1.2.840.113549.1.9.5"
					}),
					new asn1js.Set({
						value: [
							new asn1js.UTCTime({ valueDate: new Date() })
						]
					})
				]
			}),

			// messageDigest
			new asn1js.Sequence({
				value: [
					new asn1js.ObjectIdentifier({
						value: "1.2.840.113549.1.9.4"
					}),
					new asn1js.Set({
						value: [
							new asn1js.OctetString({ valueHex: Buffer.from(messageHash, "hex") })
						]
					})
				]
			}),
		]
	})
}

function getCertificateIssuerASNSequence(cert: X509Certificate): any {
	// @ts-ignore
	return asn1js.fromBER(cert.raw).result.valueBlock.value[0].valueBlock.value[3].valueBlock.value
}
function getCertificateSubjectASNSequence(cert: X509Certificate): any {
	// @ts-ignore
	return asn1js.fromBER(cert.raw).result.valueBlock.value[0].valueBlock.value[3].valueBlock.value
}
