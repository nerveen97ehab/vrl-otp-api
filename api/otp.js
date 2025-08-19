// Vercel Serverless Function: /api/otp
// POST (form-encoded): action=request|verify
// request → purpose=login|lab1|lab2
// verify  → request_id, code

export default async function handler(req, res) {
  if (req.method !== "POST") return res.status(405).end();

  // Allow form-encoded to avoid preflight
  const bodyText = req.body || "";
  const params = typeof bodyText === "string"
    ? new URLSearchParams(bodyText)
    : new URLSearchParams();

  const action = params.get("action");
  res.setHeader("Access-Control-Allow-Origin", process.env.CORS_ORIGIN || "*");

  try {
    if (action === "request") {
      const purpose = (params.get("purpose") || "").toLowerCase();
      if (!["login","lab1","lab2"].includes(purpose)) {
        return res.status(400).json({ error: "invalid purpose" });
      }
      const code = genCode();
      const requestId = cryptoRandomId();

      const ok = await storeOtp(requestId, code, purpose);
      if (!ok) return res.status(500).json({ error: "store failed" });

      const emailOk = await sendEmail({
        to: process.env.OWNER_EMAIL,
        subject: `VRL OTP for ${purpose.toUpperCase()}`,
        text: `Your one-time code is: ${code}\nIt expires in ${process.env.OTP_TTL || 300} seconds.`
      });
      if (!emailOk) return res.status(500).json({ error: "email failed" });

      return res.status(200).json({ request_id: requestId });
    }

    if (action === "verify") {
      const requestId = params.get("request_id");
      const code = params.get("code");
      if (!requestId || !code) return res.status(400).json({ error: "missing fields" });

      const entry = await getOtp(requestId);
      if (!entry) return res.status(401).json({ error: "invalid/expired" });
      if (String(entry.code) !== String(code)) return res.status(401).json({ error: "bad code" });

      await delOtp(requestId); // one-time use
      return res.status(200).json({ ok: true });
    }

    return res.status(400).json({ error: "bad action" });
  } catch (e) {
    return res.status(500).json({ error: "server error" });
  }
}

// ---------- OTP storage (Upstash Redis REST) ----------
async function storeOtp(id, code, purpose) {
  const url = process.env.UPSTASH_REDIS_REST_URL;
  const token = process.env.UPSTASH_REDIS_REST_TOKEN;
  if (!url || !token) return false;
  const ttl = parseInt(process.env.OTP_TTL || "300", 10); // seconds
  const r = await fetch(`${url}/set/${id}/${encodeURIComponent(JSON.stringify({code, purpose}))}?EX=${ttl}`, {
    headers: { Authorization: `Bearer ${token}` }
  });
  return r.ok;
}
async function getOtp(id) {
  const url = process.env.UPSTASH_REDIS_REST_URL;
  const token = process.env.UPSTASH_REDIS_REST_TOKEN;
  const r = await fetch(`${url}/get/${id}`, { headers: { Authorization: `Bearer ${token}` }});
  if (!r.ok) return null;
  const data = await r.json();
  if (!data || data.result === null) return null;
  return JSON.parse(data.result);
}
async function delOtp(id) {
  const url = process.env.UPSTASH_REDIS_REST_URL;
  const token = process.env.UPSTASH_REDIS_REST_TOKEN;
  await fetch(`${url}/del/${id}`, { headers: { Authorization: `Bearer ${token}` }});
}

// ---------- Email via Resend ----------
async function sendEmail({ to, subject, text }) {
  const apiKey = process.env.RESEND_API_KEY;
  if (!apiKey) return false;
  const from = process.env.MAIL_FROM || "no-reply@vrlcs.example";
  const r = await fetch("https://api.resend.com/emails", {
    method: "POST",
    headers: { "Authorization": `Bearer ${apiKey}`, "Content-Type":"application/json" },
    body: JSON.stringify({ from, to, subject, text })
  });
  return r.ok;
}

// ---------- helpers ----------
function genCode(){ return Math.floor(100000 + Math.random()*900000); }
function cryptoRandomId(){
  const a = new Uint8Array(16);
  crypto.getRandomValues(a);
  return [...a].map(b=>b.toString(16).padStart(2,"0")).join("");
}
