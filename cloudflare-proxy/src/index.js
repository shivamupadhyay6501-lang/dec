export default {
  async fetch(request, env, ctx) {
    const url = new URL(request.url);

    // CORS Preflight
    if (request.method === "OPTIONS") {
      return new Response(null, {
        status: 204,
        headers: {
          "Access-Control-Allow-Origin": "*",
          "Access-Control-Allow-Methods": "GET, HEAD, POST, PUT, DELETE, OPTIONS",
          "Access-Control-Allow-Headers": "*"
        }
      });
    }

    // Storage Endpoint (Cloudflare R2 Bucket API)
    if (url.pathname.startsWith("/storage")) {
      const storageKey = url.pathname.replace(/^\/storage\/?/, "");
      
      // If R2 binding is not available in local test, return mock success
      if (!env.AUDIT_BUCKET) {
        if (request.method === "GET" && storageKey === "index") {
          return new Response(JSON.stringify({ status: "mock", items: [] }), {
            headers: { "Content-Type": "application/json", "Access-Control-Allow-Origin": "*" }
          });
        }
        return new Response(JSON.stringify({ status: "r2_unbound", message: "AUDIT_BUCKET binding active on Cloudflare deployment." }), {
          headers: { "Content-Type": "application/json", "Access-Control-Allow-Origin": "*" }
        });
      }

      try {
        if (request.method === "PUT") {
          const body = await request.arrayBuffer();
          const contentType = request.headers.get("content-type") || "application/json";
          await env.AUDIT_BUCKET.put(storageKey, body, {
            httpMetadata: { contentType: contentType }
          });
          return new Response(JSON.stringify({ status: "success", key: storageKey }), {
            headers: { "Content-Type": "application/json", "Access-Control-Allow-Origin": "*" }
          });
        }

        if (request.method === "GET") {
          if (!storageKey || storageKey === "index" || storageKey === "list") {
            const prefix = url.searchParams.get("prefix") || (storageKey === "index" ? "index/" : "");
            const listed = await env.AUDIT_BUCKET.list({ prefix: prefix, limit: 100 });
            
            // If listing index, fetch all index summaries
            if (storageKey === "index") {
              const summaries = [];
              for (const obj of listed.objects) {
                const item = await env.AUDIT_BUCKET.get(obj.key);
                if (item) {
                  try {
                    const json = await item.json();
                    summaries.push(json);
                  } catch (e) {}
                }
              }
              return new Response(JSON.stringify(summaries), {
                headers: { "Content-Type": "application/json", "Access-Control-Allow-Origin": "*" }
              });
            }

            return new Response(JSON.stringify(listed), {
              headers: { "Content-Type": "application/json", "Access-Control-Allow-Origin": "*" }
            });
          }

          const object = await env.AUDIT_BUCKET.get(storageKey);
          if (!object) {
            return new Response(JSON.stringify({ error: "Not found in R2" }), {
              status: 404,
              headers: { "Content-Type": "application/json", "Access-Control-Allow-Origin": "*" }
            });
          }

          const headers = new Headers();
          object.writeHttpMetadata(headers);
          headers.set("Access-Control-Allow-Origin", "*");
          headers.set("etag", object.httpEtag);
          return new Response(object.body, { headers: headers });
        }

        if (request.method === "DELETE") {
          await env.AUDIT_BUCKET.delete(storageKey);
          return new Response(JSON.stringify({ status: "deleted", key: storageKey }), {
            headers: { "Content-Type": "application/json", "Access-Control-Allow-Origin": "*" }
          });
        }
      } catch (storageErr) {
        return new Response(JSON.stringify({ error: "R2 operation failed", details: storageErr.message }), {
          status: 500,
          headers: { "Content-Type": "application/json", "Access-Control-Allow-Origin": "*" }
        });
      }
    }

    // Health check endpoint (only when no ?url= parameter is provided)
    const targetUrl = url.searchParams.get("url");
    if (url.pathname === "/health" || (url.pathname === "/" && !targetUrl)) {
      return new Response(JSON.stringify({
        status: "online",
        service: "Cloudflare Global APK Edge Relay & R2 Storage",
        version: "2.0.0",
        r2_ready: Boolean(env.AUDIT_BUCKET)
      }), {
        headers: { "Content-Type": "application/json", "Access-Control-Allow-Origin": "*" }
      });
    }

    if (!targetUrl) {
      return new Response(JSON.stringify({ error: "Missing 'url' query parameter" }), {
        status: 400,
        headers: { "Content-Type": "application/json", "Access-Control-Allow-Origin": "*" }
      });
    }

    try {
      const headers = new Headers();
      headers.set("User-Agent", "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0.0.0 Safari/537.36");
      headers.set("Accept", "*/*");
      headers.set("Accept-Language", "en-US,en;q=0.9");
      if (targetUrl.includes("apkpure")) {
        headers.set("Referer", "https://apkpure.net/");
      } else if (targetUrl.includes("apkcombo")) {
        headers.set("Referer", "https://apkcombo.app/");
      }

      // Forward request to target mirror from Cloudflare's datacenter (US/EU/SG)
      const response = await fetch(targetUrl, {
        method: request.method,
        headers: headers,
        redirect: "follow"
      });

      // Stream the response directly back to the client
      const responseHeaders = new Headers(response.headers);
      responseHeaders.set("Access-Control-Allow-Origin", "*");
      responseHeaders.set("Access-Control-Allow-Methods", "GET, HEAD, OPTIONS");
      responseHeaders.set("X-Relayed-By", "Cloudflare-Edge-Worker");

      return new Response(response.body, {
        status: response.status,
        statusText: response.statusText,
        headers: responseHeaders
      });

    } catch (err) {
      return new Response(JSON.stringify({ error: "Proxy relay failed", message: err.message }), {
        status: 502,
        headers: { "Content-Type": "application/json" }
      });
    }
  }
};
