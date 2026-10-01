// payslip-login: 口令哈希存 auth_secret 表(服务端比对), 正确则发7天HMAC会话票
import { serve } from "https://deno.land/std@0.224.0/http/server.ts";
import { createClient } from "https://esm.sh/@supabase/supabase-js@2";
const SECRET = Deno.env.get("PAYSLIP_TOKEN");

async function sha256hex(s: string) {
  const buf = await crypto.subtle.digest("SHA-256", new TextEncoder().encode(s));
  return [...new Uint8Array(buf)].map(b => b.toString(16).padStart(2, "0")).join("");
}
async function hmac(msg: string) {
  const enc = new TextEncoder();
  const key = await crypto.subtle.importKey("raw", enc.encode(SECRET), { name: "HMAC", hash: "SHA-256" }, false, ["sign"]);
  const sig = await crypto.subtle.sign("HMAC", key, enc.encode(msg));
  return [...new Uint8Array(sig)].map(b => b.toString(16).padStart(2, "0")).join("");
}
const J = (o: unknown, s = 200) => new Response(JSON.stringify(o), { status: s, headers: { "Content-Type": "application/json", "Access-Control-Allow-Origin": "*" } });

serve(async (req: Request) => {
  if (req.method === "OPTIONS") return new Response("ok", { headers: { "Access-Control-Allow-Origin": "*", "Access-Control-Allow-Headers": "content-type" } });
  if (!SECRET) return J({ status: "ERR", msg: "not configured" }, 500);
  let body: any; try { body = await req.json(); } catch { return J({ status: "ERR" }, 400); }
  const admin = createClient(Deno.env.get("SUPABASE_URL")!, Deno.env.get("SUPABASE_SERVICE_ROLE_KEY")!, { auth: { persistSession: false } });
  const { data, error } = await admin.from("auth_secret").select("v").eq("k", "pass_hash").maybeSingle();
  if (error || !data) return J({ status: "ERR", msg: "secret store unavailable" }, 500);
  const given = await sha256hex(String(body.password || ""));
  if (given !== data.v) return J({ status: "DENIED" }, 401);
  const exp = Date.now() + 7 * 864e5;
  return J({ status: "OK", token: exp + "." + await hmac(String(exp)) });
});
