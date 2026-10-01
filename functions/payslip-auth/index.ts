// payslip-auth: 登录 + 恢复码自助重置 + 改密 三合一(按 action 分发)
// 口令均加盐哈希存 auth_secret 表(每行独立随机盐), 明文永不落库/不落前端。
import { serve } from "https://deno.land/std@0.224.0/http/server.ts";
import { createClient } from "https://esm.sh/@supabase/supabase-js@2";
const SECRET = Deno.env.get("PAYSLIP_TOKEN");

const admin = () => createClient(Deno.env.get("SUPABASE_URL")!, Deno.env.get("SUPABASE_SERVICE_ROLE_KEY")!, { auth: { persistSession: false } });

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
async function hashWith(salt: string, pwd: string) { return await sha256hex(salt + ":" + pwd); }
function genSalt() { return crypto.randomUUID(); }
function genCode() { // 一次性恢复码: XXXX-XXXX-XXXX (去易混字符)
  const A = "ABCDEFGHJKLMNPQRSTUVWXYZ23456789";
  const seg = () => Array.from(crypto.getRandomValues(new Uint8Array(4))).map(b => A[b % A.length]).join("");
  return seg() + "-" + seg() + "-" + seg();
}
async function getSecret(k: string) {
  const { data } = await admin().from("auth_secret").select("v,salt").eq("k", k).maybeSingle();
  return data ?? null;
}
async function putSecret(k: string, salt: string, v: string) {
  const { error } = await admin().from("auth_secret").upsert({ k, salt, v, updated_at: new Date().toISOString() });
  return !error;
}
const J = (o: unknown, s = 200) => new Response(JSON.stringify(o), { status: s, headers: { "Content-Type": "application/json", "Access-Control-Allow-Origin": "*" } });

async function validTicket(t: string | null): Promise<boolean> {
  if (!t || !SECRET) return false;
  const i = t.indexOf("."); if (i < 0) return false;
  const exp = t.slice(0, i), sig = t.slice(i + 1);
  if (!/^\d+$/.test(exp) || Number(exp) < Date.now()) return false;
  return (await hmac(exp)) === sig;
}

serve(async (req: Request) => {
  if (req.method === "OPTIONS") return new Response("ok", { headers: { "Access-Control-Allow-Origin": "*", "Access-Control-Allow-Headers": "content-type,x-payslip-session" } });
  if (!SECRET) return J({ status: "ERR", msg: "not configured" }, 500);
  let body: any; try { body = await req.json(); } catch { return J({ status: "ERR" }, 400); }
  const action = String(body.action || "login");
  const now = Date.now();

  if (action === "login") {
    const row = await getSecret("pass_hash");
    if (!row) return J({ status: "ERR", msg: "store unavailable" }, 500);
    if (await hashWith(row.salt, String(body.password || "")) !== row.v) return J({ status: "DENIED" }, 401);
    const exp = now + 7 * 864e5;
    return J({ status: "OK", token: exp + "." + await hmac(String(exp)) });
  }

  if (action === "recover") {
    // 恢复码自助重置: 码对 -> 设新密码 + 换发新恢复码(旧码作废)。新码只在此响应出现一次。
    const row = await getSecret("recovery_hash");
    if (!row) return J({ status: "ERR", msg: "store unavailable" }, 500);
    const codeIn = String(body.code || "").toUpperCase().replace(/\s+/g, "");
    if (await hashWith(row.salt, codeIn) !== row.v) return J({ status: "DENIED" }, 401);
    const np = String(body.new_password || "");
    if (np.length < 6 || np.length > 64) return J({ status: "ERR", msg: "新密码需6-64位" }, 400);
    const psalt = genSalt();
    if (!await putSecret("pass_hash", psalt, await hashWith(psalt, np))) return J({ status: "ERR", msg: "写入失败" }, 500);
    const newCode = genCode();
    const rsalt = genSalt();
    if (!await putSecret("recovery_hash", rsalt, await hashWith(rsalt, newCode))) return J({ status: "ERR", msg: "换码失败" }, 500);
    return J({ status: "OK", msg: "密码已重置, 新恢复码只显示这一次, 请立刻抄存", new_recovery_code: newCode });
  }

  if (action === "change") {
    // 需有效会话票; 支持改当前密码 或 轮换恢复码(reset_recovery=true)
    if (!(await validTicket(req.headers.get("x-payslip-session")))) return J({ status: "DENIED", msg: "session required" }, 401);
    const np = String(body.new_password || "");
    if (np.length && (np.length < 6 || np.length > 64)) return J({ status: "ERR", msg: "太短" }, 400);
    if (np.length) {
      const psalt = genSalt();
      if (!await putSecret("pass_hash", psalt, await hashWith(psalt, np))) return J({ status: "ERR", msg: "写入失败" }, 500);
    }
    let newCode: string | undefined;
    if (body.rotate_recovery) {
      newCode = genCode();
      const rsalt = genSalt();
      if (!await putSecret("recovery_hash", rsalt, await hashWith(rsalt, newCode))) return J({ status: "ERR", msg: "换码失败" }, 500);
    }
    return J({ status: "OK", ...(newCode ? { new_recovery_code: newCode } : {}) });
  }

  return J({ status: "ERR", msg: "unknown action" }, 400);
});
