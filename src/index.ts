/*
 * Author    : Francesco
 * Created at: 2023-12-01 11:22
 * Edited by : Francesco
 * Edited at : 2023-12-09 23:14
 *
 * Copyright (c) 2023 Xevolab S.R.L.
 */

/**
 * Some comments contain content taken from RFC 3161, RFC 5816 and RFC 2630.
 */

import { X509Certificate } from "crypto";

// Exporting the query functions
import { TimeStampReq } from "./query";
export { TimeStampReq };

// Exporting the response functions
import { TimeStampResp } from "./response";
export { TimeStampResp };

export function parseCerts(certs: string): X509Certificate[] {
	return certs.split("-----END CERTIFICATE-----").filter((j: string) => j.trim() !== "").map((j: string) => new X509Certificate(`${j}-----END CERTIFICATE-----`));
}
