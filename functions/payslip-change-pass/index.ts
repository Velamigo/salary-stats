// payslip-change-pass: 已登录(x-payslip-session票)才可改密。新密码SHA-256后存auth_secret, 明文不落任何存储。
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

async function validTicket(t: string | null): Promise<boolean> {
  if (!t || !SECRET) return false;
  const i = t.indexOf(".");
  if (i < 0) return false;
  const exp = t.slice(0, i), sig = t.slice(i + 1);
  if (!/^\d+$/.test(exp) || Number(exp) < Date.now()) return false;
  return (await hmac(exp)) === sig;
}

serve(async (req: Request) => {
  if (req.method === "OPTIONS") return new Response("ok", { headers: { "Access-Control-Allow-Origin": "*", "Access-Control-Allow-Headers": "content-type,x-payslip-session" } });
  if (!(await validTicket(req.headers.get("x-payslip-session")))) return J({ status: "DENIED", msg: "session required" }, 401);
  let body: any; try { body = await req.json(); } catch { return J({ status: "ERR" }, 400); }
  const np = String(body.new_password || "");
  if (np.length < 6) return J({ status: "ERR", msg: "太短, 至少6位" }, 400);
  if (np.length > 64) return J({ status: "ERR", msg: "太长" }, 400);
  const admin = createClient(Deno.env.get("SUPABASE_URL")!, Deno.env.get("SUPABASE_SERVICE_ROLE_KEY")!, { auth: { persistSession: false } });
  const hash = await sha256hex(np);
  const { error } = await admin.from("auth_secret").upsert({ k: "pass_hash", v: hash, updated_at: new Date().toISOString() });
  if (error) return J({ status: "ERR", msg: error.message }, 500);
  return J({ status: "OK" });
});
