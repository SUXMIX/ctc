const json = (data, status = 200, origin = "*", extra = {}) =>
  new Response(JSON.stringify(data), {
    status,
    headers: {
      "Content-Type": "application/json; charset=utf-8",
      "Access-Control-Allow-Origin": origin,
      "Access-Control-Allow-Credentials": "true",
      ...extra
    }
  });

function cors(env) {
  return env.FRONTEND_ORIGIN || "*";
}

function cookieValue(request, name) {
  const cookie = request.headers.get("Cookie") || "";
  const match = cookie.match(new RegExp("(?:^|;\\s*)" + name.replace(/[.*+?^${}()|[\\]\\\\]/g, "\\$&") + "=([^;]*)"));
  return match ? decodeURIComponent(match[1]) : null;
}

function randomToken(bytes = 32) {
  const arr = new Uint8Array(bytes);
  crypto.getRandomValues(arr);
  return [...arr].map(x => x.toString(16).padStart(2, "0")).join("");
}

async function hashPassword(password, saltHex) {
  const salt = saltHex ? hexToBytes(saltHex) : crypto.getRandomValues(new Uint8Array(16));
  const key = await crypto.subtle.importKey(
    "raw",
    new TextEncoder().encode(password),
    "PBKDF2",
    false,
    ["deriveBits"]
  );
  const bits = await crypto.subtle.deriveBits(
    {name:"PBKDF2", salt, iterations:150000, hash:"SHA-256"},
    key,
    256
  );
  return `${bytesToHex(salt)}:${bytesToHex(new Uint8Array(bits))}`;
}

async function verifyPassword(password, stored) {
  const [salt, expected] = String(stored).split(":");
  if (!salt || !expected) return false;
  const actual = (await hashPassword(password, salt)).split(":")[1];
  return constantTimeEqual(actual, expected);
}

function constantTimeEqual(a, b) {
  if (a.length !== b.length) return false;
  let result = 0;
  for (let i = 0; i < a.length; i++) result |= a.charCodeAt(i) ^ b.charCodeAt(i);
  return result === 0;
}

function bytesToHex(bytes) {
  return [...bytes].map(b => b.toString(16).padStart(2, "0")).join("");
}

function hexToBytes(hex) {
  const out = new Uint8Array(hex.length / 2);
  for (let i = 0; i < out.length; i++) out[i] = parseInt(hex.slice(i*2, i*2+2), 16);
  return out;
}

async function getUser(request, env) {
  const token = cookieValue(request, "ctc_session");
  if (!token) return null;

  const row = await env.DB.prepare(`
    SELECT users.id, users.name, users.email, users.role
    FROM sessions
    JOIN users ON users.id = sessions.user_id
    WHERE sessions.id = ? AND sessions.expires_at > ?
  `).bind(token, Date.now()).first();

  return row || null;
}

function canWrite(user) {
  return user && (user.role === "admin" || user.role === "editor");
}

async function requireUser(request, env, origin) {
  const user = await getUser(request, env);
  if (!user) return {response: json({error:"Não autenticado"}, 401, origin)};
  return {user};
}

export default {
  async fetch(request, env) {
    const origin = cors(env);
    const url = new URL(request.url);

    if (request.method === "OPTIONS") {
      return new Response(null, {
        headers: {
          "Access-Control-Allow-Origin": origin,
          "Access-Control-Allow-Credentials": "true",
          "Access-Control-Allow-Headers": "Content-Type",
          "Access-Control-Allow-Methods": "GET,POST,PUT,DELETE,OPTIONS"
        }
      });
    }

    try {
      // Público
      if (url.pathname === "/api/olympiads" && request.method === "GET") {
        const {results} = await env.DB.prepare(`
          SELECT * FROM olympiads
          ORDER BY
            CASE WHEN registration_deadline IS NULL THEN 1 ELSE 0 END,
            registration_deadline,
            acronym
        `).all();
        return json(results, 200, origin);
      }

      if (url.pathname.match(/^\\/api\\/olympiads\\/\\d+$/) && request.method === "GET") {
        const id = Number(url.pathname.split("/").pop());
        const row = await env.DB.prepare("SELECT * FROM olympiads WHERE id = ?").bind(id).first();
        if (!row) return json({error:"Não encontrada"}, 404, origin);
        return json(row, 200, origin);
      }

      // Login
      if (url.pathname === "/api/login" && request.method === "POST") {
        const body = await request.json();
        const email = String(body.email || "").trim().toLowerCase();
        const password = String(body.password || "");

        if (!email || !password) return json({error:"E-mail e senha são obrigatórios"}, 400, origin);

        const user = await env.DB.prepare(
          "SELECT id, name, email, role, password_hash FROM users WHERE email = ?"
        ).bind(email).first();

        if (!user || !(await verifyPassword(password, user.password_hash))) {
          return json({error:"E-mail ou senha inválidos"}, 401, origin);
        }

        const token = randomToken(32);
        const days = Number(env.SESSION_DAYS || 7);
        const expires = Date.now() + days * 86400000;

        await env.DB.prepare(
          "INSERT INTO sessions (id, user_id, expires_at) VALUES (?, ?, ?)"
        ).bind(token, user.id, expires).run();

        return json(
          {ok:true, user:{id:user.id,name:user.name,email:user.email,role:user.role}},
          200,
          origin,
          {"Set-Cookie": `ctc_session=${encodeURIComponent(token)}; HttpOnly; Secure; SameSite=None; Path=/; Max-Age=${days*86400}`}
        );
      }

      if (url.pathname === "/api/logout" && request.method === "POST") {
        const token = cookieValue(request, "ctc_session");
        if (token) await env.DB.prepare("DELETE FROM sessions WHERE id = ?").bind(token).run();
        return json({ok:true}, 200, origin, {
          "Set-Cookie": "ctc_session=; HttpOnly; Secure; SameSite=None; Path=/; Max-Age=0"
        });
      }

      if (url.pathname === "/api/me" && request.method === "GET") {
        const user = await getUser(request, env);
        return json(user ? {authenticated:true,user} : {authenticated:false}, 200, origin);
      }

      // Criação
      if (url.pathname === "/api/olympiads" && request.method === "POST") {
        const auth = await requireUser(request, env, origin);
        if (auth.response) return auth.response;
        if (!canWrite(auth.user)) return json({error:"Sem permissão"}, 403, origin);

        const b = await request.json();
        if (!b.acronym || !b.name) return json({error:"Sigla e nome são obrigatórios"}, 400, origin);

        const result = await env.DB.prepare(`
          INSERT INTO olympiads
          (acronym,name,area,modality,registration_method,registration_deadline,
           number_of_phases,phase_1_date,phase_2_date,phase_3_date,phase_4_date,status,extra)
          VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?)
        `).bind(
          b.acronym,b.name,b.area||null,b.modality||null,b.registration_method||null,
          b.registration_deadline||null,b.number_of_phases ?? null,b.phase_1_date||null,
          b.phase_2_date||null,b.phase_3_date||null,b.phase_4_date||null,b.status||null,b.extra||null
        ).run();

        return json({ok:true,id:result.meta.last_row_id}, 201, origin);
      }

      // Edição
      if (url.pathname.match(/^\\/api\\/olympiads\\/\\d+$/) && request.method === "PUT") {
        const auth = await requireUser(request, env, origin);
        if (auth.response) return auth.response;
        if (!canWrite(auth.user)) return json({error:"Sem permissão"}, 403, origin);

        const id = Number(url.pathname.split("/").pop());
        const b = await request.json();

        await env.DB.prepare(`
          UPDATE olympiads SET
            acronym=?, name=?, area=?, modality=?, registration_method=?,
            registration_deadline=?, number_of_phases=?, phase_1_date=?,
            phase_2_date=?, phase_3_date=?, phase_4_date=?, status=?, extra=?,
            updated_at=CURRENT_TIMESTAMP
          WHERE id=?
        `).bind(
          b.acronym,b.name,b.area||null,b.modality||null,b.registration_method||null,
          b.registration_deadline||null,b.number_of_phases ?? null,b.phase_1_date||null,
          b.phase_2_date||null,b.phase_3_date||null,b.phase_4_date||null,b.status||null,b.extra||null,id
        ).run();

        return json({ok:true}, 200, origin);
      }

      // Exclusão
      if (url.pathname.match(/^\\/api\\/olympiads\\/\\d+$/) && request.method === "DELETE") {
        const auth = await requireUser(request, env, origin);
        if (auth.response) return auth.response;
        if (auth.user.role !== "admin") return json({error:"Somente administradores podem excluir"}, 403, origin);

        const id = Number(url.pathname.split("/").pop());
        await env.DB.prepare("DELETE FROM olympiads WHERE id = ?").bind(id).run();
        return json({ok:true}, 200, origin);
      }

      return json({error:"Rota não encontrada"}, 404, origin);
    } catch (error) {
      console.error(error);
      return json({error:"Erro interno do servidor"}, 500, origin);
    }
  }
};
