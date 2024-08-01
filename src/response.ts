/*
 * Author    : Francesco
 * Created at: 2023-12-09 17:52
 * Edited by : Francesco
 * Edited at : 2024-07-31 19:56
 *
 * Copyright (c) 2023 Xevolab S.R.L.
 */
/* eslint-disable max-len */
/* eslint-disable lines-between-class-members */

import {
	KeyObject, X509Certificate, sign, randomBytes, createHash,
} from "crypto";
import * as asn1js from "asn1js";

import { hashAlgOID } from "./parseOID";
import {
	keyForAlg, getSignedAttributes,
	getCertificateIssuerASNSequence, getCertificateSubjectASNSequence,
} from "./responseUtils";

export type SignOptions = {
	signingHashAlgorithm?: "SHA256" | "SHA384" | "SHA512",

	externalSignature?: boolean
}

export class TimeStampResp {
	// Parameters
	public hashedMessage: Buffer | string;
	public hashAlgorithm: string;
	public version?: number;
	public reqPolicy?: string;
	public nonce?: number | Buffer | Uint8Array;
	public certReq?: boolean;

	// Credentials
	private key?: KeyObject;
	public certs?: X509Certificate[];

	// Response
	public signingTime!: Date;
	public serialNumber!: Buffer;
	public buffer!: Buffer;
	private asn1!: asn1js.Sequence;

	// Signature
	public payloadDigest?: Buffer;
	public signedDigest?: Buffer;

	/**
	 * Creates an instance of TimeStampResp.
	 * This class is used to generate a response
	 *
	 * @param   {string|Buffer}  hashedMessage  The hashed message
	 * @param   {KeyObject}        key            The private key of the TSA
	 * @param   {X509Certificate[]}  certs          The certificate chain of the TSA
	 * @param   {string}           hashAlgorithm  The hash algorithm used to hash the message
	 * @param   {number|Buffer|Uint8Array}  nonce          The nonce
	 * @param   {boolean}          certReq        Whether to include the certificate chain in the res
	 */
	constructor(hashedMessage: string | Buffer, {
		hashAlgorithm,

		version,
		reqPolicy,
		nonce,
		certReq,

		key,
		certs,

		signingOptions,
	}: {
		hashAlgorithm: string,

		version?: number,
		reqPolicy?: string,
		nonce?: number | Buffer | Uint8Array,
		certReq?: boolean,

		key?: KeyObject,
		certs?: X509Certificate[],

		signingOptions?: SignOptions,
	}) {
		this.hashedMessage = hashedMessage;
		this.hashAlgorithm = hashAlgorithm;

		this.version = version || 1;
		this.reqPolicy = reqPolicy || "1.2.3.4";
		this.nonce = nonce;
		this.certReq = certReq;

		this.key = key;
		this.certs = certs;

		this.buffer = this.sign(signingOptions);
	}

	public sign(opts?: SignOptions): Buffer {
		const { signingHashAlgorithm = "SHA512" } = opts || {};

		// --> Validating payload

		const { key, certs } = this;
		let { hashAlgorithm, hashedMessage } = this;

		/**
		 * hashAlgorithm must be a string that rappresent the hash algorithm used to hash the message
		 * Valid values are: SHA-256, SHA-384, SHA-512
		 */
		if (typeof hashAlgorithm !== "string") throw new Error("Invalid hashAlgorithm; needs to be a string.");

		hashAlgorithm = hashAlgorithm.toUpperCase().replaceAll("-", "");
		const hashAlgs = ["SHA256", "SHA384", "SHA512"];
		if (!hashAlgs.includes(hashAlgorithm)) throw new Error(`Invalid hashAlgorithm; needs to be one of ${hashAlgs.join(", ")}.`);

		/**
		 * hashedMessage must be a Buffer or a hex string that rappresent the hashed message
		 */
		if (typeof hashedMessage === "string") {
			if (!/^[0-9A-F]+$/i.test(hashedMessage)) throw new Error("Invalid hashedMessage; if a string is passed, it needs to be a hex string.");
			hashedMessage = Buffer.from(hashedMessage, "hex");
		}
		if (!Buffer.isBuffer(hashedMessage)) throw new Error("Invalid hashedMessage; needs to be a buffer (or a hex string).");

		// --> Loading the key(s)

		if (key && !(key instanceof KeyObject)) throw new Error("Invalid key; needs to be a KeyObject.");
		if (!key && !opts?.externalSignature) throw new Error("Missing key. Please, provide a key or enable external signature function.");

		// --> Loading the certificates

		if (!Array.isArray(certs)) throw new Error("Invalid certs; needs to be an array.");
		if (certs.length === 0) throw new Error("Invalid certs; needs to be an array with at least one element.");

		this.signingTime = new Date();
		this.serialNumber = randomBytes(6);

		/**
		 * TSTInfo ::= SEQUENCE  {
		 *   version                      INTEGER  { v1(1), v2(2) },
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
				// TODO: support v1 and get version from request
				// NOTE: is it really needed?
				new asn1js.Integer({ value: this.version }),

				/**
				 * TSAPolicyId ::= OBJECT IDENTIFIER
				 * The policy identifier for the time stamping service, as defined in RFC 3161.
				 */
				new asn1js.ObjectIdentifier({ value: this.reqPolicy }),

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
									value: hashAlgOID[hashAlgorithm],
								}),
								new asn1js.Null(),
							],
						}),
						// hashedMessage
						new asn1js.OctetString({ valueHex: hashedMessage }),
					],
				}),

				/**
				 * CertificateSerialNumber ::= INTEGER
				 */
				asn1js.Integer.fromBigInt(`0x${this.serialNumber.toString("hex")}`),

				/**
				 * GeneralizedTime ::= CHOICE {
				 *   utcTime        UTCTime,
				 *   generalTime    GeneralizedTime
				 * }
				 */
				new asn1js.GeneralizedTime({ valueDate: this.signingTime }),

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
				 *
				 * Insert number as
				 */
				...(this.nonce ? [new asn1js.Integer(
					{
						valueHex: this.nonce instanceof Buffer ? this.nonce : Buffer.from(this.nonce.toString(16), "hex"),
					},
				)] : []),

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
								value: getCertificateSubjectASNSequence(certs[0]),
							})],
						}),
					],
				}),
			],
		});

		this.payloadDigest = createHash(signingHashAlgorithm)
			.update(Buffer.from(payload.toBER(false)))
			.digest();

		// --> Generating the signature

		// The signature is generated using the private key of the TSA, by signing the DER encoded
		// payload and, if present, the signed attributes.
		let signature = Buffer.from((new asn1js.Set({
			value: getSignedAttributes(this.payloadDigest, this.signingTime, certs),
		}).toBER(false)));
		this.signedDigest = createHash(signingHashAlgorithm).update(signature).digest();

		// If the signature is generated using an external signer, the signature is filled with only
		// the hash of the payload.
		if (opts?.externalSignature || !key) signature = Buffer.from("00", "hex");
		else signature = sign(signingHashAlgorithm, signature, keyForAlg(key));


		/**
		 * TimeStampResp ::= SEQUENCE  {
		 *   status                  PKIStatusInfo,
		 *   timeStampToken          TimeStampToken     OPTIONAL
		 * }
		 */

		const Resp = new asn1js.Sequence();

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
		Resp.valueBlock.value.push(new asn1js.Sequence({
			value: [
				// status
				new asn1js.Integer({ value: 0 }),
				// statusString
				// new asn1js.Sequence({ value: [new asn1js.Utf8String({ value: "Granted" })] }),
				// failInfo
				// new asn1js.BitString({ valueHex: new ArrayBuffer(1) }),
			],
		})); // status

		/**
		 * TimeStampToken ::= ContentInfo
		 *   -- contentType is id-signedData
		 *   -- content is SignedData
		 */
		Resp.valueBlock.value.push(new asn1js.Sequence({
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
												value: hashAlgOID[signingHashAlgorithm],
											}),
											new asn1js.Null(),
										],
									}),
								],
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

										value: [new asn1js.OctetString({ valueHex: Buffer.from(payload.toBER(false)) })],
									}),
								],
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
							...(this.certReq ? [new asn1js.Constructed({
								idBlock: { tagClass: 3, tagNumber: 0 },
								value: certs.map(c => new asn1js.Sequence({
									value: asn1js.fromBER(c.raw).result.valueBlock.value,
								})),
							})] : []),

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
											new asn1js.Integer({ value: 1 }),

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
													new asn1js.Sequence({ value: getCertificateIssuerASNSequence(certs[0]) }),
													// serialNumber
													new asn1js.Integer({ valueHex: Buffer.from(certs[0].serialNumber, "hex") }),
												],
											}),

											/**
											 * DigestAlgorithmIdentifier ::= AlgorithmIdentifier
											 */
											new asn1js.Sequence({
												value: [
													new asn1js.ObjectIdentifier({
														value: hashAlgOID[signingHashAlgorithm],
													}),
													new asn1js.Null(),
												],
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
											new asn1js.Constructed({
												idBlock: { tagClass: 3, tagNumber: 0 },
												value: getSignedAttributes(this.payloadDigest, this.signingTime, certs),
											}),

											/**
											 * SignatureAlgorithmIdentifier ::= AlgorithmIdentifier
											 */
											new asn1js.Sequence({
												value: [
													new asn1js.ObjectIdentifier({
														value: "1.2.840.113549.1.1.1", // rsaEncryption
													}),
													new asn1js.Null(),
												],
											}),

											/**
											 * SignatureValue ::= OCTET STRING
											 */
											new asn1js.OctetString({
												valueHex: signature,
											}),

										],
									}),
								],
							}),
						],
					}),
					],
				})],
		}));

		this.asn1 = Resp;
		return Buffer.from(Resp.toBER(false));
	}

	public setSignature(signature: Buffer) {
		const index1 = this.asn1.valueBlock.value[1].valueBlock.value[1].valueBlock.value[0].valueBlock.value.length - 1;
		const index2 = this.asn1.valueBlock.value[1].valueBlock.value[1].valueBlock.value[0].valueBlock.value[index1].valueBlock.value[0].valueBlock.value.length - 1;

		this.asn1.valueBlock.value[1].valueBlock.value[1].valueBlock.value[0].valueBlock.value[index1].valueBlock.value[0].valueBlock.value[index2] = new asn1js.OctetString({
			valueHex: signature,
		});

		this.buffer = Buffer.from(this.asn1.toBER(false));
	}
}
