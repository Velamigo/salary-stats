// payslip-ingest: cron 专用写入口。校验共享口令(secret: PAYSLIP_TOKEN)后以 service role 幂等入库。
// 调用: POST {body:{period, rows:[...]}}  Header: x-payslip-token: ***
import { serve } from "https://deno.land/std@0.224.0/http/server.ts";
import { createClient } from "https://esm.sh/@supabase/supabase-js@2";

const TOKEN = Deno.env.get("PAYSLIP_TOKEN");

serve(async (req: Request) => {
  if (req.method === "OPTIONS") return new Response("ok", { headers: { "Access-Control-Allow-Origin": "*", "Access-Control-Allow-Headers": "content-type,x-payslip-token" } });
  if (req.headers.get("x-payslip-token") !== TOKEN || !TOKEN) {
    return new Response(JSON.stringify({ status: "DENIED" }), { status: 401, headers: { "Content-Type": "application/json" } });
  }
  let body: any;
  try { body = await req.json(); } catch { return new Response(JSON.stringify({ status: "ERR", msg: "bad json" }), { status: 400, headers: { "Content-Type": "application/json" } }); }
  const period = String(body.period || "");
  const rows = Array.isArray(body.rows) ? body.rows : [];
  if (!/^\d{6}$/.test(period) || rows.length === 0 || rows.length > 500) {
    return new Response(JSON.stringify({ status: "ERR", msg: "bad payload" }), { status: 400, headers: { "Content-Type": "application/json" } }); }
  const supabase = createClient(
    Deno.env.get("SUPABASE_URL")!,
    Deno.env.get("SUPABASE_SERVICE_ROLE_KEY")!,
    { auth: { persistSession: false } });
  // 幂等：先删该月旧行再插
  const { error: delErr } = await supabase.from("payslips").delete().eq("period", period);
  if (delErr) return new Response(JSON.stringify({ status: "ERR", msg: "delete: " + delErr.message }), { status: 500, headers: { "Content-Type": "application/json" } });
  const payload = rows.map((r: any) => ({
    period, net_pay: r.net_pay ?? null, gross: r.gross ?? null,
    category: String(r.category || ""), item_name: String(r.item_name || ""),
    item_value: r.item_value ?? null }));
  const { error: insErr } = await supabase.from("payslips").insert(payload);
  if (insErr) return new Response(JSON.stringify({ status: "ERR", msg: "insert: " + insErr.message }), { status: 500, headers: { "Content-Type": "application/json" } });
  return new Response(JSON.stringify({ status: "OK", period, rows: payload.length }), { status: 201, headers: { "Content-Type": "application/json" } });
});
