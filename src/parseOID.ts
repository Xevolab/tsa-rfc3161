/*
 * Author    : Francesco
 * Created at: 2023-12-09 16:39
 * Edited by : Francesco
 * Edited at : 2023-12-09 23:17
 *
 * Copyright (c) 2023 Xevolab S.R.L.
 */

export function parseOID(bytes: number[]) {
	const first = Math.floor(bytes[0] / 40) + "." + bytes[0] % 40;

	return first + "." + bytes.slice(1).join(".");
}

export const hashAlgIdentifier: any = {
	"2.16.840.1.101.3.4.2.1": "SHA256",
	"2.16.840.1.101.3.4.2.2": "SHA384",
	"2.16.840.1.101.3.4.2.3": "SHA512"
}
export const hashAlgOID: any = {
	"SHA256": "2.16.840.1.101.3.4.2.1",
	"SHA384": "2.16.840.1.101.3.4.2.2",
	"SHA512": "2.16.840.1.101.3.4.2.3"
}
