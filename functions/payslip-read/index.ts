// payslip-read: 唯一读入口。前端不再持有数据库key——
// 必须带 payslip-login 签发的会话票(HMAC校验+7天过期)，服务端持service key查库后返回。
// 无票/坏票/过期 = 401，数据库里一行都看不到。
import { serve } from "https://deno.land/std@0.224.0/http/server.ts";
const SECRET = Deno.env.get("PAYSLIP_TOKEN");

async function hmac(msg: string) {
  const enc = new TextEncoder();
  const key = await crypto.subtle.importKey("raw", enc.encode(SECRET), { name: "HMAC", hash: "SHA-256" }, false, ["sign"]);
  const sig = await crypto.subtle.sign("HMAC", key, enc.encode(msg));
  return [...new Uint8Array(sig)].map(b => b.toString(16).padStart(2, "0")).join("");
}

const J = (o: unknown, s = 200) => new Response(JSON.stringify(o), { status: s, headers: { "Content-Type": "application/json", "Access-Control-Allow-Origin": "*", ...(s === 401 ? { "www-authenticate": "session" } : {}) } });

async function validTicket(t: string | null): Promise<boolean> {
  if (!t || !SECRET) return false;
  const i = t.indexOf(".");
  if (i < 0) return false;
  const exp = t.slice(0, i), sig = t.slice(i + 1);
  if (!/^\d+$/.test(exp) || Number(exp) < Date.now()) return false;
  return (await hmac(exp)) === sig;
}

serve(async (req: Request) => {
  if (req.method === "OPTIONS") return new Response("ok", { headers: { "Access-Control-Allow-Origin": "*", "Access-Control-Allow-Headers": "content-type,x-payslip-session,x-payslip-token" } });
  // 两种可信通道: 浏览器会话票 / cron 专用固定口令(改页面密码不影响它)
  if (req.headers.get("x-payslip-token") !== SECRET && !(await validTicket(req.headers.get("x-payslip-session")))) return J({ status: "DENIED", msg: "session required" }, 401);
  const { createClient } = await import("https://esm.sh/@supabase/supabase-js@2");
  const supabase = createClient(Deno.env.get("SUPABASE_URL")!, Deno.env.get("SUPABASE_SERVICE_ROLE_KEY")!, { auth: { persistSession: false } });
  const { data, error } = await supabase.from("payslips").select("period,category,item_name,item_value").order("period", { ascending: true });
  if (error) return J({ status: "ERR", msg: error.message }, 500);
  return J({ status: "OK", rows: data ?? [] });
});
