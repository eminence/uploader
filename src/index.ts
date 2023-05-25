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
// import index_data from "./index.html";
const index_data = `<!DOCTYPE html>
<html>

<head>
    <link rel="icon" href="https://up.em32.site/sjg5RY04jB-5ZYP2N+ga7w==" />
    <style>
        body {
            font-family: monospace;
            font-size: larger;
        }

        button {
            font-family: monospace;
        }

        div#dropzone {
            background-color: lightblue;
            position: fixed;
            left: 20px;
            top: 20px;
            bottom: 20px;
            right: 20px;
            display: flex;
            justify-content: center;
            align-items: center;
            flex-direction: column;
        }

        div#dropzone * {
            margin: 3px;
            padding: 3px;
        }

        div#dropzone input[type=file] {
            display: none;
        }
    </style>
    <script type="text/javascript">
        function process_event(dataTransfer) {
            for (const item of dataTransfer.items) {
                console.log(item, item.kind, item.type);
                if (item.kind === "string" && item.type != "vscode-editor-data") {
                    upload(dataTransfer.getData(item.type), item.type);
                }
            }
            for (const item of dataTransfer.files) {
                console.log(item)
                if (item.type.startsWith("image/") || item.type.startsWith("video/")) {
                    upload(item.arrayBuffer(), item.type);
                }
            }
        }

        function selectfile(event) {
            document.getElementById("file").click()
        }

        function handleFiles(event) {
            for (const file of document.getElementById("file").files) {
                upload(file.arrayBuffer(), file.type);
            }
        }

        function contentTypeAllowed(contentType) {
            return true;
            return contentType.startsWith("audio/") ||
                contentType.startsWith("video/") ||
                contentType.startsWith("image/") ||
                contentType.startsWith("text/");
        }

        function allowDrop(allowdropevent) {
            allowdropevent.preventDefault();
            console.log(allowdropevent)

            document.getElementById("dropzone").style.backgroundColor = "lightgreen";
            for (const item of allowdropevent.dataTransfer.items) {
                console.log("items", item, item.kind, item.type);
                if (item.type.length > 0 && !item.type.startsWith("image/") && !item.type.startsWith("video/")) {
                    document.querySelector("#dropzone span#msg").innerText = item.type + " not supported"
                    document.getElementById("dropzone").style.backgroundColor = "lightcoral";
                    break;
                }
            }
            for (const item of allowdropevent.dataTransfer.files) {
                console.log("files", item)
            }
        }

        function leavedrag(event) {
            document.getElementById("dropzone").style.backgroundColor = "lightblue";
            document.querySelector("#dropzone span#msg").innerText = "";
        }

        function drop(dropevent) {
            dropevent.preventDefault();
            document.getElementById("dropzone").style.backgroundColor = "lightblue";
            document.querySelector("#dropzone span#msg").innerText = "";
            process_event(dropevent.dataTransfer);
        }

        async function upload(data, contentType) {
            const elem = document.getElementById("results");
            const li = document.createElement("li");
            elem.appendChild(li);
            li.innerHTML = "Uploading............... " + contentType;

            const resp = await fetch("/", {
                "method": "POST",
                "body": await data,
                "headers": {
                    "Content-Type": contentType
                }
            });
            const result = new URL(await resp.text());
            console.log(result);

            const link = document.createElement("a");
            link.href = result.pathname;
            link.innerText = result.pathname.substring(1) + " " + contentType;
            link.target = "_blank";
            li.innerHTML = "";
            li.appendChild(link);
        }

        document.addEventListener("paste", (event) => {
            event.preventDefault();
            console.log(event);
            process_event(event.clipboardData);
        });
    </script>
</head>

<body>
    <div id="dropzone" ondrop="drop(event)" ondragover="allowDrop(event);" ondragleave="leavedrag(event)"
        ondragend="leavedrag(event)">
        <span>Paste data or drop here or <button onclick="selectfile(event)">click here</button></span>
        <input type="file" id="file" onchange="handleFiles(event)" multiple />
        <span id="msg"></span>
        <ul id="results"></ul>
    </div>
</body>

</html>
`;

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
}

const chars = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+-';

const encode = (arraybuffer: ArrayBuffer): string => {
	let bytes = new Uint8Array(arraybuffer),
		i,
		len = bytes.length,
		base64 = '';

	for (i = 0; i < len; i += 3) {
		base64 += chars[bytes[i] >> 2];
		base64 += chars[((bytes[i] & 3) << 4) | (bytes[i + 1] >> 4)];
		base64 += chars[((bytes[i + 1] & 15) << 2) | (bytes[i + 2] >> 6)];
		base64 += chars[bytes[i + 2] & 63];
	}

	if (len % 3 === 2) {
		base64 = base64.substring(0, base64.length - 1) + '=';
	} else if (len % 3 === 1) {
		base64 = base64.substring(0, base64.length - 2) + '==';
	}

	return base64;
};

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

const save_stream = async (env: Env, value: ReadableStream, length: number, contentType?: string, contentLength?: number, cf?: any): Promise<string> => {
	const digestStream = new crypto.DigestStream("MD5");
	const tee = value.tee();
	const uuid = crypto.randomUUID();



	tee[0].pipeTo(digestStream);

	let stored_in_kv: boolean;

	// if small enough, store directly in KV
	if (length < 20 * 1024 * 1024) {
		await env.kv_upload.put(uuid, tee[1], {
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
		const put_obj = await env.r2_uploads.put(uuid, tee[1], {
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
	const encoded = encode(calculated_digest);
	console.log("calculated digest", hexString, encoded, uuid);

	const now = Date.now().valueOf();
	const expires_sec = calc_expiration_secsfromnow(length);
	try {
		const stmt = await env.DB.prepare('INSERT OR REPLACE INTO aliases (alias, uuid, blob, created, expires, cf) VALUES (?1, ?2, ?3, ?4, ?5, ?6)')
			.bind(encoded, uuid, stored_in_kv ? "kv" : "r2", now, now + (expires_sec * 1000), JSON.stringify(cf)).run();
	} catch (e) {
		console.log("error inserting alias", e);

	}

	return encoded;
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

			if (contentType === "") {
				console.log("Incoming request is missing content-type header");
				return new Response("go away", { status: 400 });
			}
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

				const encoded = await save_stream(env, file.stream(), file.size, undefined, file.size, request.cf);
				return new Response(`https://up.em32.site/${encoded}`);
			} else {
				const encoded = await save_stream(env, request.body, contentLength, contentType, contentLength, request.cf);
				return new Response(`https://up.em32.site/${encoded}`);
			}

		} else if (request.method == "GET") {
			if (url.pathname === "/_/list" || url.pathname === "/_/delete") {
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
					const stmt = await env.DB.prepare('SELECT alias, uuid, blob, created, expires, cf FROM aliases order by created desc limit 10').run();
					if (stmt.success && stmt.results) {
						const to_return = [] as any[];
						for (const result of stmt.results as AliasDbRow[]) {
							const o = {
								alias: result.alias,
								uuid: result.uuid,
								blob: result.blob,
								created: new Date(result.created).toISOString(),
								expires: new Date(result.expires).toISOString(),
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
							console.log("deleting", key.name, key.metadata, key.expiration);
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