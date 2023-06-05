/**
 * Welcome to Cloudflare Workers! This is your first worker.
 *
 * - Run `wrangler dev src/index.ts` in your terminal to start a development server
 * - Open a browser tab at http://localhost:8787/ to see your worker in action
 * - Run `wrangler publish src/index.ts --name my-worker` to publish your worker
 *
 * Learn more at https://developers.cloudflare.com/workers/
 */

// import * as mime from "mime-types";
import { slowTee } from "../slow-tee/src";
import index_data from "./index.html";
import list_data from "./list.html";

import { initSync, add, infer } from "./infer/infer_wasm";
import wasm_mod from "./infer/infer_wasm_bg.wasm";


export interface Env {
	// Example binding to KV. Learn more at https://developers.cloudflare.com/workers/runtime-apis/kv/
	// MY_KV_NAMESPACE: KVNamespace;
	kv_upload: KVNamespace;
	//
	// Example binding to Durable Object. Learn more at https://developers.cloudflare.com/workers/runtime-apis/durable-objects/
	// MY_DURABLE_OBJECT: DurableObjectNamespace;
	//
	// Example binding to R2. Learn more at https://developers.cloudflare.com/workers/runtime-apis/r2/
	// MY_BUCKET: R2Bucket;
	r2_uploads: R2Bucket;

	DB: D1Database;

	// secrets
	ADMIN_PASSWORD: string;

	LOCAL_DEV?: string;
}

const base58_encode = (arraybuffer: ArrayBuffer): string => {
	// Copyright (c) 2021 pur3miish
	// https://github.com/pur3miish/base58-js
	const alphabet = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz";

	const base58Map = Array(256).fill(-1);
	for (let i = 0; i < alphabet.length; ++i)
		base58Map[alphabet.charCodeAt(i)] = i;

	let bytes = new Uint8Array(arraybuffer);

	const result = [];

	for (const byte of bytes) {
		let carry = byte;
		for (let j = 0; j < result.length; ++j) {
			const x: any = (base58Map[result[j]] << 8) + carry;
			result[j] = alphabet.charCodeAt(x % 58);
			carry = (x / 58) | 0;
		}
		while (carry) {
			result.push(alphabet.charCodeAt(carry % 58));
			carry = (carry / 58) | 0;
		}
	}

	for (const byte of bytes)
		if (byte) break;
		else result.push("1".charCodeAt(0));

	result.reverse();

	return String.fromCharCode(...result);
}

interface KVMetadata {
	/* if true, the data is a blob in KV and can be served directly from KV */
	blob?: boolean;
	/* if "kv" then this is an alias for a KV blob, else it's an r2 blob */
	alias?: "kv" | "r2";
	"content-type"?: string;
	"content-length"?: number;
}

interface AliasDbRow {
	alias: string;
	uuid: string;
	blob: string;
	created: number;
	expires: number;
	cf: string;

}

const stream_kv_blob = (value: ReadableStream | null, metadata: KVMetadata | null): Response => {
	if (value === null) {
		return new Response("not found in kv", { status: 404 });
	}
	// check metadata to see if we should stream the result directly to the client, of it it looks like an alias
	if (metadata) {
		const headers = new Headers();
		if (metadata["content-type"]) {
			headers.set("content-type", metadata["content-type"]);
		}
		if (metadata["content-length"]) {
			headers.set("content-length", metadata["content-length"].toString());
		}
		return new Response(value, {
			headers,
		});
	}

	return new Response("error", { status: 500 });
};

const calc_expiration_secsfromnow = (file_size: number): number => {
	const min_age = 30; // 30 days
	const max_age = 365; // 1 year
	const max_size = 100 * 1024 * 1024; // 100 Mb limit from CF
	const ttl_in_days = min_age + (-max_age + min_age) * Math.pow((file_size / max_size - 1), 3);

	return ttl_in_days * 86400;
}

const save_stream = async (env: Env, value: ReadableStream, length: number, contentType?: string, contentLength?: number, cf?: any): Promise<{ encoded: string, contentType?: string }> => {
	const digestStream = new crypto.DigestStream("SHA-256");
	const uuid = crypto.randomUUID();


	let tee;
	if (contentType === null || contentType === "") {
		// try to guess the type
		tee = slowTee(value, ["hasher", "uploader", "guesser"]);
		initSync(wasm_mod);
		const rc = await infer(tee.guesser);
		if (rc != null) {
			contentType = rc;
			console.log("Detected content type:", contentType);
		} else {
			console.log("Failed to detect content type, using application/octet-stream");
			contentType = "application/octet-stream";
		}
	} else {
		tee = slowTee(value, ["hasher", "uploader",]);
	}

	tee.hasher.pipeTo(digestStream);

	let stored_in_kv: boolean;

	// if small enough, store directly in KV
	if (length < 20 * 1024 * 1024) {
		await env.kv_upload.put(uuid, tee.uploader, {
			expirationTtl: calc_expiration_secsfromnow(length),
			metadata: {
				"blob": true,
				"content-type": contentType,
				"content-length": contentLength,
			} as KVMetadata
		});
		stored_in_kv = true;
	} else {
		// upload to R2
		const put_obj = await env.r2_uploads.put(uuid, tee.uploader, {
			// md5: hash,
			httpMetadata: {
				contentType: contentType,
			}
		});
		stored_in_kv = false;
	}

	const calculated_digest = await digestStream.digest;
	const hexString = [...new Uint8Array(calculated_digest)]
		.map(b => b.toString(16).padStart(2, '0'))
		.join('');
	const encoded = base58_encode(calculated_digest);
	console.log("calculated digest", hexString, encoded, uuid);

	const now = Date.now().valueOf();
	const expires_sec = calc_expiration_secsfromnow(length);

	// find the shortest prefix of `encoded` that's not already in our alias database
	let db_error;
	for (let i = 4; i <= encoded.length; i++) {
		const prefix = encoded.substring(0, i);
		// try to insert the prefix, and if it fails, retry with a longer prefix
		try {
			const stmt = await env.DB.prepare('INSERT OR FAIL INTO aliases (alias, uuid, blob, created, expires, cf) VALUES (?1, ?2, ?3, ?4, ?5, ?6)')
				.bind(prefix, uuid, stored_in_kv ? "kv" : "r2", now, now + (expires_sec * 1000), JSON.stringify(cf)).run();
			return { encoded: prefix, contentType: contentType };
		} catch (e) {
			console.log("error inserting alias", prefix, "trying again with a longer prefix", e);
			db_error = e;
		}
	}

	// we couldn't insert, so throw our most recent error
	throw db_error;


	// try {
	// 	const stmt = await env.DB.prepare('INSERT OR REPLACE INTO aliases (alias, uuid, blob, created, expires, cf) VALUES (?1, ?2, ?3, ?4, ?5, ?6)')
	// 		.bind(encoded, uuid, stored_in_kv ? "kv" : "r2", now, now + (expires_sec * 1000), JSON.stringify(cf)).run();
	// } catch (e) {
	// 	console.log("error inserting alias", e);
	// }

	// return encoded;
};

export default {
	async fetch(
		request: Request,
		env: Env,
		ctx: ExecutionContext
	): Promise<Response> {
		const { cf, headers } = request;
		const contentType = headers.get('content-type') || '';
		const contentLengthStr = headers.get('content-length');
		const url = new URL(request.url);

		if (request.method == "PUT" || request.method == "POST") {
			console.log(`Received POST with contentType=${contentType} length=${contentLengthStr}`);
			// const hash = url.searchParams.get("hash");
			// if (hash === null || hash.length !== 32) {
			// 	console.log("Incoming request is missing hash query param")
			// 	return new Response("go away", { status: 400 });
			// }

			if (contentLengthStr === null) {
				console.log("Incoming request is missing content-length header");
				return new Response("go away", { status: 400 });
			}
			const contentLength = parseInt(contentLengthStr);
			if (request.body === null) {
				console.log("Incoming request is missing body");
				return new Response("go away", { status: 400 });
			}

			// const incoming_hash = new Uint8Array(16).map((_elem, idx) => { return parseInt(hash.substring(idx * 2, idx * 2 + 2), 16) })
			// const encoded = encode(incoming_hash);

			if (contentType.includes("multipart/form-data")) {
				const form = await request.formData();
				const file: null | File = form.get("file") as any;
				if (file === null) {
					return new Response("go away", { status: 400 });
				}

				const { encoded, contentType } = await save_stream(env, file.stream(), file.size, undefined, file.size, request.cf);
				if (url.searchParams.get("resp") === "json") {
					return new Response(JSON.stringify({ encoded: `https://up.em32.site/${encoded}`, contentType }), {
						headers: {
							"content-type": "application/json;charset=UTF-8",
						}
					});
				} else {
					return new Response(`https://up.em32.site/${encoded}`);
				}
			} else {
				try {
					const { encoded, contentType: detectedType } = await save_stream(env, request.body, contentLength, contentType, contentLength, request.cf);
					if (url.searchParams.get("resp") === "json") {
						return new Response(JSON.stringify({
							encoded: `https://up.em32.site/${encoded}`,
							contentType: detectedType
						}), {
							headers: {
								"content-type": "application/json;charset=UTF-8",
							}
						});
					} else {
						return new Response(`https://up.em32.site/${encoded}`);
					}
				} catch (e) {
					console.log(e);
				}
			}

		} else if (request.method == "GET") {
			if (url.pathname === "/wasm") {
				initSync(wasm_mod);
				const rc = add(4, 8);
				console.log(rc);
				return new Response("go away", { status: 400 });
			}
			if (url.pathname === "/favicon.ico") {
				const { value, metadata } = await env.kv_upload.getWithMetadata<KVMetadata>("cecd07db-d608-49da-88a7-a88773a64930", { type: "stream" });
				if (value === null) {
					return new Response("not found in kv", { status: 404 });
				}
				return stream_kv_blob(value, metadata);

			}
			if (url.pathname.startsWith("/_/")) {
				if (cf && (cf as any).metroCode === "521" && headers.get("Authorization") === "Basic " + env.ADMIN_PASSWORD) {
					console.log("login ok from", JSON.stringify(cf));
				} else {
					return new Response("not found", {
						status: 401,
						headers: {
							"WWW-Authenticate": "Basic"
						}
					})
				}
				if (url.pathname == "/_/list") {
					return new Response(list_data, {
						headers: {
							"content-type": "text/html; charset=utf-8",
						}
					});
				}

				if (url.pathname == "/_/list.json") {
					const limit = url.searchParams.get("limit") || "10";
					// make sure limit is an int, between 1 and 100
					const limit_int = parseInt(limit);
					if (limit_int < 1 || limit_int > 100) {
						return new Response("go away", { status: 400 });
					}

					const offset = url.searchParams.get("offset") || "0";
					// offset must be not negative
					const offset_int = parseInt(offset);
					if (offset_int < 0) {
						return new Response("go away", { status: 400 });
					}

					const stmt = await env.DB.prepare(`SELECT alias, uuid, blob, created, expires, cf FROM aliases order by created desc limit ${limit} offset ${offset}`).run();
					if (stmt.success && stmt.results) {
						const to_return = [] as any[];
						for (const result of stmt.results as AliasDbRow[]) {
							const o = {
								alias: result.alias,
								uuid: result.uuid,
								blob: result.blob,
								created: new Date(result.created).toISOString(),
								created_ts: result.created,
								expires: new Date(result.expires).toISOString(),
								expires_ts: result.expires,
								cf: JSON.parse(result.cf),
							} as any;
							if (result.blob == "kv") {
								const kv_data = await env.kv_upload.list({ prefix: result.uuid });
								if (kv_data.keys.length == 1) {
									o['kv_metadata'] = {
										expires: new Date((kv_data.keys[0] as any).expiration * 1000).toISOString(),
										metadata: kv_data.keys[0].metadata,
									};
								}

							} else if (result.blob == "r2") {
								const r2_data = await env.r2_uploads.list({
									prefix: result.uuid,
									limit: 1,
								});
								// console.log(JSON.stringify(r2_data));
								o['r2_metadata'] = r2_data.objects[0];
							}
							to_return.push(o);
						}
						return new Response(JSON.stringify(to_return, null, 2), {
							headers: {
								"content-type": "application/json;charset=UTF-8",
							},
						});
					}
				} else if (url.pathname == "/_/delete") {
					// iterate through KV entries looking for things that don't have an alias entry
					const list = await env.kv_upload.list<KVMetadata>();
					for (const key of list.keys) {
						const stmt = await env.DB.prepare('SELECT * FROM aliases WHERE alias = ?1').bind(key.name).run();
						if (stmt.success && stmt.results && stmt.results.length == 0) {
							console.log("deleting", key.name, key.metadata, new Date(key.expiration as number * 1000));
							return new Response(key.name, { status: 400 });
							// await env.kv_upload.delete(key.name);
						} else {
							console.log(key.metadata, key.name);
						}
					}
				}

				return new Response("go away", { status: 400 });
			}

			if (url.pathname.length > 1) {

				// look up alias in D1 database
				const stmt = await env.DB.prepare('SELECT alias, uuid, blob, created, expires, cf FROM aliases WHERE alias = ?1').bind(url.pathname.substring(1)).run();
				if (stmt.success && stmt.results && stmt.results.length > 0) {
					const alias_row = stmt.results[0] as AliasDbRow;
					if (alias_row.blob == "kv") {
						const { value, metadata } = await env.kv_upload.getWithMetadata<KVMetadata>(alias_row.uuid, { type: "stream" });
						if (value === null) {
							return new Response("not found in kv", { status: 404 });
						}
						return stream_kv_blob(value, metadata);
					} else if (alias_row.blob == "r2") {
						const r2_object = await env.r2_uploads.get(alias_row.uuid);
						if (r2_object === null) {
							return new Response("not found in r2", { status: 404 });
						}
						const headers = new Headers();
						r2_object.writeHttpMetadata(headers);
						headers.set('etag', r2_object.httpEtag);

						return new Response(r2_object.body, {
							headers,
						});
					}
				} else {
					console.log("Missing from d1, trying KV anyway");
					// alias might be KV, look here
					const { value, metadata } = await env.kv_upload.getWithMetadata<KVMetadata>(url.pathname.substring(1), { type: "stream" });
					if (value === null) {
						return new Response("not found in kv", { status: 404 });
					}
					if (metadata?.blob) {
						return stream_kv_blob(value, metadata);
					}
					if (metadata?.alias) {
						// refetch as text to look up the UUID
						const { value, metadata } = await env.kv_upload.getWithMetadata<KVMetadata>(url.pathname.substring(1), { type: "text" });
						console.log("redirect blob", value);
					}
					return new Response("not found in d1", { status: 404 });

				}

				return new Response("go away");
			}
		}

		return new Response(index_data, {
			headers: {
				"content-type": "text/html; charset=utf-8",
			}
		});
	},
};
