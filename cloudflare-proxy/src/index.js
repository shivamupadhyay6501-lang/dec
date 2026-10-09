export default {
  async fetch(request, env, ctx) {
    const url = new URL(request.url);

    // Health check endpoint
    if (url.pathname === "/health" || url.pathname === "/") {
      return new Response(JSON.stringify({
        status: "online",
        service: "Cloudflare Global APK Edge Relay",
        version: "1.0.0"
      }), {
        headers: { "Content-Type": "application/json" }
      });
    }

    const targetUrl = url.searchParams.get("url");
    if (!targetUrl) {
      return new Response(JSON.stringify({ error: "Missing 'url' query parameter" }), {
        status: 400,
        headers: { "Content-Type": "application/json" }
      });
    }

    try {
      const headers = new Headers();
      headers.set("User-Agent", "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0.0.0 Safari/537.36");
      headers.set("Accept", "*/*");
      headers.set("Accept-Language", "en-US,en;q=0.9");

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
