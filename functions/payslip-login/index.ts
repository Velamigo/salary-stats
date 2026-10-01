// payslip-login: 口令在服务端比对，前端源码零密码零key；正确则发7天HMAC会话票
import { serve } from "https://deno.land/std@0.224.0/http/server.ts";
const PASS = Deno.env.get("PAYSLIP_PASS");
const SECRET = Deno.env.get("PAYSLIP_TOKEN");

async function hmac(msg: string) {
  const enc = new TextEncoder();
  const key = await crypto.subtle.importKey("raw", enc.encode(SECRET), { name: "HMAC", hash: "SHA-256" }, false, ["sign"]);
  const sig = await crypto.subtle.sign("HMAC", key, enc.encode(msg));
  return [...new Uint8Array(sig)].map(b => b.toString(16).padStart(2, "0")).join("");
}

const J = (o: unknown, s = 200) => new Response(JSON.stringify(o), { status: s, headers: { "Content-Type": "application/json", "Access-Control-Allow-Origin": "*" } });

serve(async (req: Request) => {
  if (req.method === "OPTIONS") return new Response("ok", { headers: { "Access-Control-Allow-Origin": "*", "Access-Control-Allow-Headers": "content-type" } });
  if (!PASS || !SECRET) return J({ status: "ERR", msg: "not configured" }, 500);
  let body: any; try { body = await req.json(); } catch { return J({ status: "ERR" }, 400); }
  if (String(body.password || "") !== PASS) return J({ status: "DENIED" }, 401);
  const exp = Date.now() + 7 * 864e5;
  const token = exp + "." + await hmac(String(exp));
  return J({ status: "OK", token });
});
