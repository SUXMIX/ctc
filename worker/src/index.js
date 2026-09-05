const JSON_HEADERS = {
  "Content-Type": "application/json; charset=utf-8",
};

export default {
  async fetch(request, env) {
    const url = new URL(request.url);

    // =========================
    // CORS
    // =========================

    const origin = request.headers.get("Origin");
    const allowedOrigin = env.FRONTEND_ORIGIN || "";

    const corsHeaders = {
      "Access-Control-Allow-Methods": "GET, POST, PUT, DELETE, OPTIONS",
      "Access-Control-Allow-Headers": "Content-Type",
      "Access-Control-Allow-Credentials": "true",
      "Vary": "Origin",
    };

    if (origin && origin === allowedOrigin) {
      corsHeaders["Access-Control-Allow-Origin"] = origin;
    }

    if (request.method === "OPTIONS") {
      return new Response(null, {
        status: 204,
        headers: corsHeaders,
      });
    }

    // =========================
    // Helpers
    // =========================

    function json(data, status = 200, extraHeaders = {}) {
      return new Response(JSON.stringify(data), {
        status,
        headers: {
          ...JSON_HEADERS,
          ...corsHeaders,
          ...extraHeaders,
        },
      });
    }

    function error(message, status = 400) {
      return json({ error: message }, status);
    }

    function parseCookies(request) {
      const cookieHeader = request.headers.get("Cookie") || "";
      const cookies = {};

      for (const part of cookieHeader.split(";")) {
        const index = part.indexOf("=");

        if (index === -1) continue;

        const key = part.slice(0, index).trim();
        const value = part.slice(index + 1).trim();

        cookies[key] = value;
      }

      return cookies;
    }

    function getSessionToken(request) {
      const cookies = parseCookies(request);
      return cookies.ctc_session || null;
    }

    function sessionCookie(token, maxAge) {
      return [
        `ctc_session=${token}`,
        "Path=/",
        "HttpOnly",
        "Secure",
        "SameSite=None",
        `Max-Age=${maxAge}`,
      ].join("; ");
    }

    function clearSessionCookie() {
      return [
        "ctc_session=",
        "Path=/",
        "HttpOnly",
        "Secure",
        "SameSite=None",
        "Max-Age=0",
      ].join("; ");
    }

    async function getCurrentUser(request) {
      const token = getSessionToken(request);

      if (!token) {
        return null;
      }

      const result = await env.DB.prepare(`
        SELECT
          users.id,
          users.username,
          users.name,
          users.role
        FROM sessions
        INNER JOIN users ON users.id = sessions.user_id
        WHERE sessions.token = ?
          AND sessions.expires_at > datetime('now')
      `)
        .bind(token)
        .first();

      return result || null;
    }

    function requireRole(user, roles) {
      if (!user) {
        return error("Não autenticado.", 401);
      }

      if (!roles.includes(user.role)) {
        return error("Acesso negado.", 403);
      }

      return null;
    }

    async function generateToken() {
      const bytes = new Uint8Array(32);
      crypto.getRandomValues(bytes);

      return [...bytes]
        .map((byte) => byte.toString(16).padStart(2, "0"))
        .join("");
    }

    async function hashPassword(password, salt = null) {
      const encoder = new TextEncoder();

      const passwordBytes = encoder.encode(password);

      let saltBytes;

      if (salt) {
        saltBytes = Uint8Array.from(atob(salt), (char) =>
          char.charCodeAt(0)
        );
      } else {
        saltBytes = new Uint8Array(16);
        crypto.getRandomValues(saltBytes);
      }

      const keyMaterial = await crypto.subtle.importKey(
        "raw",
        passwordBytes,
        "PBKDF2",
        false,
        ["deriveBits"]
      );

      const derivedBits = await crypto.subtle.deriveBits(
        {
          name: "PBKDF2",
          salt: saltBytes,
          iterations: 150000,
          hash: "SHA-256",
        },
        keyMaterial,
        256
      );

      const hashBytes = new Uint8Array(derivedBits);

      const hash = [...hashBytes]
        .map((byte) => byte.toString(16).padStart(2, "0"))
        .join("");

      const saltBase64 = btoa(
        String.fromCharCode(...saltBytes)
      );

      return {
        hash,
        salt: saltBase64,
      };
    }

    async function verifyPassword(password, storedHash, storedSalt) {
      const result = await hashPassword(password, storedSalt);
      return result.hash === storedHash;
    }

    function normalizeOlympiad(body) {
      return {
        acronym: body.acronym?.trim() || null,
        name: body.name?.trim() || null,
        area: body.area?.trim() || null,
        modality: body.modality?.trim() || null,
        registration_method:
          body.registration_method?.trim() || null,
        registration_deadline:
          body.registration_deadline || null,
        number_of_phases:
          body.number_of_phases === "" ||
          body.number_of_phases === null ||
          body.number_of_phases === undefined
            ? null
            : Number(body.number_of_phases),
        phase_1_date: body.phase_1_date || null,
        phase_2_date: body.phase_2_date || null,
        phase_3_date: body.phase_3_date || null,
        phase_4_date: body.phase_4_date || null,
        status: body.status?.trim() || null,
        extra: body.extra?.trim() || null,
      };
    }

    // =========================
    // API
    // =========================

    // Página inicial do Worker
    if (url.pathname === "/" && request.method === "GET") {
      return json({
        ok: true,
        service: "CTC API",
        message: "API funcionando.",
      });
    }

    // =========================
    // LOGIN
    // =========================

    if (url.pathname === "/api/login" && request.method === "POST") {
      let body;

      try {
        body = await request.json();
      } catch {
        return error("JSON inválido.");
      }

      const username = body.username?.trim();
      const password = body.password;

      if (!username || !password) {
        return error("Usuário e senha são obrigatórios.");
      }

      const user = await env.DB.prepare(`
        SELECT
          id,
          username,
          name,
          role,
          password_hash,
          password_salt
        FROM users
        WHERE username = ?
      `)
        .bind(username)
        .first();

      if (!user) {
        return error("Usuário ou senha incorretos.", 401);
      }

      const valid = await verifyPassword(
        password,
        user.password_hash,
        user.password_salt
      );

      if (!valid) {
        return error("Usuário ou senha incorretos.", 401);
      }

      const token = await generateToken();

      const sessionDays = Number(env.SESSION_DAYS || 7);

      const maxAge = sessionDays * 24 * 60 * 60;

      await env.DB.prepare(`
        INSERT INTO sessions (
          token,
          user_id,
          expires_at
        )
        VALUES (
          ?,
          ?,
          datetime('now', ?)
        )
      `)
        .bind(
          token,
          user.id,
          `+${sessionDays} days`
        )
        .run();

      return json(
        {
          ok: true,
          user: {
            id: user.id,
            username: user.username,
            name: user.name,
            role: user.role,
          },
        },
        200,
        {
          "Set-Cookie": sessionCookie(token, maxAge),
        }
      );
    }

    // =========================
    // LOGOUT
    // =========================

    if (url.pathname === "/api/logout" && request.method === "POST") {
      const token = getSessionToken(request);

      if (token) {
        await env.DB.prepare(`
          DELETE FROM sessions
          WHERE token = ?
        `)
          .bind(token)
          .run();
      }

      return json(
        {
          ok: true,
        },
        200,
        {
          "Set-Cookie": clearSessionCookie(),
        }
      );
    }

    // =========================
    // USUÁRIO ATUAL
    // =========================

    if (url.pathname === "/api/me" && request.method === "GET") {
      const user = await getCurrentUser(request);

      if (!user) {
        return json({
          authenticated: false,
          user: null,
        });
      }

      return json({
        authenticated: true,
        user,
      });
    }

    // =========================
    // LISTAR OLIMPÍADAS
    // GET /api/olympiads
    // =========================

    if (
      url.pathname === "/api/olympiads" &&
      request.method === "GET"
    ) {
      const result = await env.DB.prepare(`
        SELECT
          id,
          acronym,
          name,
          area,
          modality,
          registration_method,
          registration_deadline,
          number_of_phases,
          phase_1_date,
          phase_2_date,
          phase_3_date,
          phase_4_date,
          status,
          extra,
          created_at,
          updated_at
        FROM olympiads
        ORDER BY
          registration_deadline IS NULL,
          registration_deadline ASC,
          acronym ASC
      `).all();

      return json({
        olympiads: result.results || [],
      });
    }

    // =========================
    // BUSCAR UMA OLIMPÍADA
    // GET /api/olympiads/:id
    // =========================

    const olympiadMatch = url.pathname.match(
      /^\/api\/olympiads\/(\d+)$/
    );

    if (olympiadMatch && request.method === "GET") {
      const id = Number(olympiadMatch[1]);

      const olympiad = await env.DB.prepare(`
        SELECT
          id,
          acronym,
          name,
          area,
          modality,
          registration_method,
          registration_deadline,
          number_of_phases,
          phase_1_date,
          phase_2_date,
          phase_3_date,
          phase_4_date,
          status,
          extra,
          created_at,
          updated_at
        FROM olympiads
        WHERE id = ?
      `)
        .bind(id)
        .first();

      if (!olympiad) {
        return error("Olimpíada não encontrada.", 404);
      }

      return json(olympiad);
    }

    // =========================
    // CRIAR OLIMPÍADA
    // POST /api/olympiads
    // =========================

    if (
      url.pathname === "/api/olympiads" &&
      request.method === "POST"
    ) {
      const user = await getCurrentUser(request);

      const denied = requireRole(user, ["admin", "editor"]);

      if (denied) {
        return denied;
      }

      let body;

      try {
        body = await request.json();
      } catch {
        return error("JSON inválido.");
      }

      const data = normalizeOlympiad(body);

      if (!data.acronym) {
        return error("A sigla é obrigatória.");
      }

      if (!data.name) {
        return error("O nome da olimpíada é obrigatório.");
      }

      if (
        data.number_of_phases !== null &&
        (!Number.isInteger(data.number_of_phases) ||
          data.number_of_phases < 1 ||
          data.number_of_phases > 4)
      ) {
        return error(
          "O número de fases deve estar entre 1 e 4."
        );
      }

      const result = await env.DB.prepare(`
        INSERT INTO olympiads (
          acronym,
          name,
          area,
          modality,
          registration_method,
          registration_deadline,
          number_of_phases,
          phase_1_date,
          phase_2_date,
          phase_3_date,
          phase_4_date,
          status,
          extra,
          created_at,
          updated_at
        )
        VALUES (
          ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, datetime('now'), datetime('now')
        )
      `)
        .bind(
          data.acronym,
          data.name,
          data.area,
          data.modality,
          data.registration_method,
          data.registration_deadline,
          data.number_of_phases,
          data.phase_1_date,
          data.phase_2_date,
          data.phase_3_date,
          data.phase_4_date,
          data.status,
          data.extra
        )
        .run();

      return json(
        {
          ok: true,
          id: result.meta.last_row_id,
        },
        201
      );
    }

    // =========================
    // EDITAR OLIMPÍADA
    // PUT /api/olympiads/:id
    // =========================

    if (olympiadMatch && request.method === "PUT") {
      const user = await getCurrentUser(request);

      const denied = requireRole(user, ["admin", "editor"]);

      if (denied) {
        return denied;
      }

      const id = Number(olympiadMatch[1]);

      let body;

      try {
        body = await request.json();
      } catch {
        return error("JSON inválido.");
      }

      const data = normalizeOlympiad(body);

      if (!data.acronym) {
        return error("A sigla é obrigatória.");
      }

      if (!data.name) {
        return error("O nome da olimpíada é obrigatório.");
      }

      if (
        data.number_of_phases !== null &&
        (!Number.isInteger(data.number_of_phases) ||
          data.number_of_phases < 1 ||
          data.number_of_phases > 4)
      ) {
        return error(
          "O número de fases deve estar entre 1 e 4."
        );
      }

      const result = await env.DB.prepare(`
        UPDATE olympiads
        SET
          acronym = ?,
          name = ?,
          area = ?,
          modality = ?,
          registration_method = ?,
          registration_deadline = ?,
          number_of_phases = ?,
          phase_1_date = ?,
          phase_2_date = ?,
          phase_3_date = ?,
          phase_4_date = ?,
          status = ?,
          extra = ?,
          updated_at = datetime('now')
        WHERE id = ?
      `)
        .bind(
          data.acronym,
          data.name,
          data.area,
          data.modality,
          data.registration_method,
          data.registration_deadline,
          data.number_of_phases,
          data.phase_1_date,
          data.phase_2_date,
          data.phase_3_date,
          data.phase_4_date,
          data.status,
          data.extra,
          id
        )
        .run();

      if (result.meta.changes === 0) {
        return error("Olimpíada não encontrada.", 404);
      }

      return json({
        ok: true,
      });
    }

    // =========================
    // EXCLUIR OLIMPÍADA
    // DELETE /api/olympiads/:id
    // =========================

    if (olympiadMatch && request.method === "DELETE") {
      const user = await getCurrentUser(request);

      const denied = requireRole(user, ["admin"]);

      if (denied) {
        return denied;
      }

      const id = Number(olympiadMatch[1]);

      const result = await env.DB.prepare(`
        DELETE FROM olympiads
        WHERE id = ?
      `)
        .bind(id)
        .run();

      if (result.meta.changes === 0) {
        return error("Olimpíada não encontrada.", 404);
      }

      return json({
        ok: true,
      });
    }

    // =========================
    // ROTA NÃO ENCONTRADA
    // =========================

    return error("Rota não encontrada.", 404);
  },
};
