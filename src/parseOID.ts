/*
 * Author    : Francesco
 * Created at: 2023-12-09 16:39
 * Edited by : Francesco
 * Edited at : 2023-12-09 16:48
 *
 * Copyright (c) 2023 Xevolab S.R.L.
 */

export function parseOID(bytes: number[]) {
	const first = Math.floor(bytes[0] / 40) + "." + bytes[0] % 40;

	return first + "." + bytes.slice(1).join(".");
}
