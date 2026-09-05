const PBKDF2_ITERATIONS = 100000;
const SESSION_COOKIE_NAME = "ctc_session";

// ============================================================
// CONFIGURAÇÕES
// ============================================================

function getFrontendOrigin(env) {
  return env.FRONTEND_ORIGIN || "https://suxmix.github.io";
}

// ============================================================
// RESPOSTAS / CORS
// ============================================================

function corsHeaders(request, env) {
  const origin = request.headers.get("Origin");
  const allowedOrigin = getFrontendOrigin(env);

  const headers = {
    "Access-Control-Allow-Methods": "GET, POST, PUT, DELETE, OPTIONS",
    "Access-Control-Allow-Headers": "Content-Type, X-Bootstrap-Secret",
    "Access-Control-Allow-Credentials": "true",
    "Vary": "Origin",
  };

  if (origin === allowedOrigin) {
    headers["Access-Control-Allow-Origin"] = origin;
  }

  return headers;
}

function json(data, status = 200, headers = {}) {
  return new Response(JSON.stringify(data), {
    status,
    headers: {
      "Content-Type": "application/json; charset=utf-8",
      ...headers,
    },
  });
}

function response(request, env, data, status = 200, extraHeaders = {}) {
  return json(data, status, {
    ...corsHeaders(request, env),
    ...extraHeaders,
  });
}

// ============================================================
// COOKIE
// ============================================================

function createSessionCookie(token, maxAge) {
  return [
    `${SESSION_COOKIE_NAME}=${token}`,
    `Max-Age=${maxAge}`,
    "Path=/",
    "HttpOnly",
    "Secure",
    "SameSite=None",
  ].join("; ");
}

function createExpiredSessionCookie() {
  return [
    `${SESSION_COOKIE_NAME}=`,
    "Max-Age=0",
    "Path=/",
    "HttpOnly",
    "Secure",
    "SameSite=None",
  ].join("; ");
}

function getCookie(request, name) {
  const cookieHeader = request.headers.get("Cookie");

  if (!cookieHeader) {
    return null;
  }

  const cookies = cookieHeader.split(";");

  for (const cookie of cookies) {
    const separator = cookie.indexOf("=");

    if (separator === -1) {
      continue;
    }

    const key = cookie.slice(0, separator).trim();
    const value = cookie.slice(separator + 1).trim();

    if (key === name) {
      return value;
    }
  }

  return null;
}

// ============================================================
// CRIPTOGRAFIA / SENHAS
// ============================================================

function bytesToHex(bytes) {
  return Array.from(bytes)
    .map((byte) => byte.toString(16).padStart(2, "0"))
    .join("");
}

function hexToBytes(hex) {
  if (!hex || hex.length % 2 !== 0) {
    throw new Error("Hexadecimal inválido.");
  }

  const bytes = new Uint8Array(hex.length / 2);

  for (let i = 0; i < bytes.length; i++) {
    bytes[i] = parseInt(hex.slice(i * 2, i * 2 + 2), 16);
  }

  return bytes;
}

function constantTimeEqual(a, b) {
  if (a.length !== b.length) {
    return false;
  }

  let result = 0;

  for (let i = 0; i < a.length; i++) {
    result |= a[i] ^ b[i];
  }

  return result === 0;
}

async function derivePasswordHash(password, salt, iterations) {
  const encoder = new TextEncoder();

  const keyMaterial = await crypto.subtle.importKey(
    "raw",
    encoder.encode(password),
    "PBKDF2",
    false,
    ["deriveBits"]
  );

  const derivedBits = await crypto.subtle.deriveBits(
    {
      name: "PBKDF2",
      salt,
      iterations,
      hash: "SHA-256",
    },
    keyMaterial,
    256
  );

  return new Uint8Array(derivedBits);
}

async function createPasswordHash(password) {
  const salt = crypto.getRandomValues(new Uint8Array(16));

  const hash = await derivePasswordHash(
    password,
    salt,
    PBKDF2_ITERATIONS
  );

  return [
    "pbkdf2",
    PBKDF2_ITERATIONS,
    bytesToHex(salt),
    bytesToHex(hash),
  ].join("$");
}

async function verifyPassword(password, storedHash) {
  try {
    const parts = storedHash.split("$");

    if (parts.length !== 4) {
      return false;
    }

    const algorithm = parts[0];
    const iterations = Number(parts[1]);
    const saltHex = parts[2];
    const hashHex = parts[3];

    if (algorithm !== "pbkdf2") {
      return false;
    }

    if (!Number.isInteger(iterations) || iterations <= 0) {
      return false;
    }

    const salt = hexToBytes(saltHex);
    const expectedHash = hexToBytes(hashHex);

    const actualHash = await derivePasswordHash(
      password,
      salt,
      iterations
    );

    return constantTimeEqual(actualHash, expectedHash);
  } catch {
    return false;
  }
}

// ============================================================
// SESSÃO
// ============================================================

function generateSessionToken() {
  const bytes = crypto.getRandomValues(new Uint8Array(32));
  return bytesToHex(bytes);
}

async function createSession(env, userId) {
  const token = generateSessionToken();

  const sessionDays = Number(env.SESSION_DAYS || 7);

  const maxAge = Math.max(
    1,
    sessionDays * 24 * 60 * 60
  );

  const expiresAt = Math.floor(Date.now() / 1000) + maxAge;

  await env.DB.prepare(
    `
    INSERT INTO sessions (id, user_id, expires_at)
    VALUES (?, ?, ?)
    `
  )
    .bind(token, userId, expiresAt)
    .run();

  return {
    token,
    maxAge,
    expiresAt,
  };
}

async function getAuthenticatedUser(request, env) {
  const token = getCookie(
    request,
    SESSION_COOKIE_NAME
  );

  if (!token) {
    return null;
  }

  const now = Math.floor(Date.now() / 1000);

  const result = await env.DB.prepare(
    `
    SELECT
      users.id,
      users.name,
      users.email,
      users.role
    FROM sessions
    INNER JOIN users
      ON users.id = sessions.user_id
    WHERE sessions.id = ?
      AND sessions.expires_at > ?
    LIMIT 1
    `
  )
    .bind(token, now)
    .first();

  return result || null;
}

async function deleteSession(request, env) {
  const token = getCookie(
    request,
    SESSION_COOKIE_NAME
  );

  if (!token) {
    return;
  }

  await env.DB.prepare(
    `
    DELETE FROM sessions
    WHERE id = ?
    `
  )
    .bind(token)
    .run();
}

// ============================================================
// AUXILIARES
// ============================================================

async function readJson(request) {
  try {
    return await request.json();
  } catch {
    return null;
  }
}

function isValidEmail(email) {
  return (
    typeof email === "string" &&
    email.length <= 254 &&
    /^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(email)
  );
}

function requireAuthenticatedUser(user) {
  return user !== null;
}

function requireEditor(user) {
  return (
    user &&
    (user.role === "editor" || user.role === "admin")
  );
}

function requireAdmin(user) {
  return user && user.role === "admin";
}

// ============================================================
// HEALTH CHECK
// ============================================================

async function handleRoot(request, env) {
  return response(request, env, {
    ok: true,
    service: "ctc-api",
    message: "API do CTC funcionando.",
  });
}

// ============================================================
// LOGIN
// ============================================================

async function handleLogin(request, env) {
  const body = await readJson(request);

  if (!body) {
    return response(
      request,
      env,
      {
        error: "JSON inválido.",
      },
      400
    );
  }

  const email =
    typeof body.email === "string"
      ? body.email.trim().toLowerCase()
      : "";

  const password =
    typeof body.password === "string"
      ? body.password
      : "";

  if (!isValidEmail(email) || !password) {
    return response(
      request,
      env,
      {
        error: "Email ou senha inválidos.",
      },
      400
    );
  }

  const user = await env.DB.prepare(
    `
    SELECT
      id,
      name,
      email,
      password_hash,
      role
    FROM users
    WHERE LOWER(email) = ?
    LIMIT 1
    `
  )
    .bind(email)
    .first();

  if (!user) {
    return response(
      request,
      env,
      {
        error: "Email ou senha inválidos.",
      },
      401
    );
  }

  const validPassword = await verifyPassword(
    password,
    user.password_hash
  );

  if (!validPassword) {
    return response(
      request,
      env,
      {
        error: "Email ou senha inválidos.",
      },
      401
    );
  }

  // Remove sessões antigas do usuário.
  await env.DB.prepare(
    `
    DELETE FROM sessions
    WHERE user_id = ?
    `
  )
    .bind(user.id)
    .run();

  const session = await createSession(
    env,
    user.id
  );

  return response(
    request,
    env,
    {
      ok: true,
      user: {
        id: user.id,
        name: user.name,
        email: user.email,
        role: user.role,
      },
    },
    200,
    {
      "Set-Cookie": createSessionCookie(
        session.token,
        session.maxAge
      ),
    }
  );
}

// ============================================================
// ME
// ============================================================

async function handleMe(request, env) {
  const user = await getAuthenticatedUser(
    request,
    env
  );

  if (!user) {
    return response(
      request,
      env,
      {
        authenticated: false,
      },
      200
    );
  }

  return response(
    request,
    env,
    {
      authenticated: true,
      user,
    },
    200
  );
}

// ============================================================
// LOGOUT
// ============================================================

async function handleLogout(request, env) {
  await deleteSession(request, env);

  return response(
    request,
    env,
    {
      ok: true,
    },
    200,
    {
      "Set-Cookie": createExpiredSessionCookie(),
    }
  );
}

// ============================================================
// OLIMPÍADAS — LISTAR
// ============================================================

async function handleListOlympiads(
  request,
  env
) {
  const result = await env.DB.prepare(
    `
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
    `
  ).all();

  return response(
    request,
    env,
    {
      olympiads: result.results || [],
    }
  );
}

// ============================================================
// OLIMPÍADAS — UMA
// ============================================================

async function handleGetOlympiad(
  request,
  env,
  id
) {
  const olympiad = await env.DB.prepare(
    `
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
    LIMIT 1
    `
  )
    .bind(id)
    .first();

  if (!olympiad) {
    return response(
      request,
      env,
      {
        error: "Olimpíada não encontrada.",
      },
      404
    );
  }

  return response(
    request,
    env,
    {
      olympiad,
    }
  );
}

// ============================================================
// OLIMPÍADAS — CRIAR
// ============================================================

async function handleCreateOlympiad(
  request,
  env
) {
  const user = await getAuthenticatedUser(
    request,
    env
  );

  if (!requireEditor(user)) {
    return response(
      request,
      env,
      {
        error: "Acesso não autorizado.",
      },
      401
    );
  }

  const body = await readJson(request);

  if (!body) {
    return response(
      request,
      env,
      {
        error: "JSON inválido.",
      },
      400
    );
  }

  const acronym = body.acronym || "";
  const name = body.name || "";
  const area = body.area || "";
  const modality = body.modality || "";
  const registrationMethod =
    body.registration_method || "";
  const registrationDeadline =
    body.registration_deadline || null;

  const numberOfPhases =
    body.number_of_phases !== undefined &&
    body.number_of_phases !== null &&
    body.number_of_phases !== ""
      ? Number(body.number_of_phases)
      : null;

  const phase1 = body.phase_1_date || null;
  const phase2 = body.phase_2_date || null;
  const phase3 = body.phase_3_date || null;
  const phase4 = body.phase_4_date || null;

  const status = body.status || "";
  const extra = body.extra || "";

  if (!acronym || !name) {
    return response(
      request,
      env,
      {
        error:
          "A sigla e o nome da olimpíada são obrigatórios.",
      },
      400
    );
  }

  const now = new Date().toISOString();

  const result = await env.DB.prepare(
    `
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
    VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
    `
  )
    .bind(
      acronym,
      name,
      area,
      modality,
      registrationMethod,
      registrationDeadline,
      numberOfPhases,
      phase1,
      phase2,
      phase3,
      phase4,
      status,
      extra,
      now,
      now
    )
    .run();

  return response(
    request,
    env,
    {
      ok: true,
      id: result.meta.last_row_id,
    },
    201
  );
}

// ============================================================
// OLIMPÍADAS — EDITAR
// ============================================================

async function handleUpdateOlympiad(
  request,
  env,
  id
) {
  const user = await getAuthenticatedUser(
    request,
    env
  );

  if (!requireEditor(user)) {
    return response(
      request,
      env,
      {
        error: "Acesso não autorizado.",
      },
      401
    );
  }

  const body = await readJson(request);

  if (!body) {
    return response(
      request,
      env,
      {
        error: "JSON inválido.",
      },
      400
    );
  }

  const existing = await env.DB.prepare(
    `
    SELECT *
    FROM olympiads
    WHERE id = ?
    LIMIT 1
    `
  )
    .bind(id)
    .first();

  if (!existing) {
    return response(
      request,
      env,
      {
        error: "Olimpíada não encontrada.",
      },
      404
    );
  }

  const acronym =
    body.acronym ?? existing.acronym;

  const name =
    body.name ?? existing.name;

  const area =
    body.area ?? existing.area;

  const modality =
    body.modality ?? existing.modality;

  const registrationMethod =
    body.registration_method ??
    existing.registration_method;

  const registrationDeadline =
    body.registration_deadline ??
    existing.registration_deadline;

  const numberOfPhases =
    body.number_of_phases !== undefined
      ? (
          body.number_of_phases === null ||
          body.number_of_phases === ""
            ? null
            : Number(body.number_of_phases)
        )
      : existing.number_of_phases;

  const phase1 =
    body.phase_1_date ??
    existing.phase_1_date;

  const phase2 =
    body.phase_2_date ??
    existing.phase_2_date;

  const phase3 =
    body.phase_3_date ??
    existing.phase_3_date;

  const phase4 =
    body.phase_4_date ??
    existing.phase_4_date;

  const status =
    body.status ?? existing.status;

  const extra =
    body.extra ?? existing.extra;

  const updatedAt =
    new Date().toISOString();

  await env.DB.prepare(
    `
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
      updated_at = ?
    WHERE id = ?
    `
  )
    .bind(
      acronym,
      name,
      area,
      modality,
      registrationMethod,
      registrationDeadline,
      numberOfPhases,
      phase1,
      phase2,
      phase3,
      phase4,
      status,
      extra,
      updatedAt,
      id
    )
    .run();

  return response(
    request,
    env,
    {
      ok: true,
    }
  );
}

// ============================================================
// OLIMPÍADAS — EXCLUIR
// ============================================================

async function handleDeleteOlympiad(
  request,
  env,
  id
) {
  const user = await getAuthenticatedUser(
    request,
    env
  );

  if (!requireAdmin(user)) {
    return response(
      request,
      env,
      {
        error: "Apenas administradores podem excluir.",
      },
      403
    );
  }

  const result = await env.DB.prepare(
    `
    DELETE FROM olympiads
    WHERE id = ?
    `
  )
    .bind(id)
    .run();

  if (!result.meta.changes) {
    return response(
      request,
      env,
      {
        error: "Olimpíada não encontrada.",
      },
      404
    );
  }

  return response(
    request,
    env,
    {
      ok: true,
    }
  );
}

// ============================================================
// BOOTSTRAP DO PRIMEIRO ADMINISTRADOR
// ============================================================

async function handleBootstrapAdmin(
  request,
  env
) {
  const secret =
    request.headers.get("X-Bootstrap-Secret");

  if (
    !secret ||
    !env.ADMIN_BOOTSTRAP_SECRET ||
    secret !== env.ADMIN_BOOTSTRAP_SECRET
  ) {
    return response(
      request,
      env,
      {
        error: "Não autorizado.",
      },
      401
    );
  }

  const existingAdmin = await env.DB.prepare(
    `
    SELECT id
    FROM users
    WHERE role = 'admin'
    LIMIT 1
    `
  ).first();

  if (existingAdmin) {
    return response(
      request,
      env,
      {
        error:
          "O administrador inicial já foi criado.",
      },
      409
    );
  }

  const body = await readJson(request);

  if (!body) {
    return response(
      request,
      env,
      {
        error: "JSON inválido.",
      },
      400
    );
  }

  const name =
    typeof body.name === "string"
      ? body.name.trim()
      : "";

  const email =
    typeof body.email === "string"
      ? body.email.trim().toLowerCase()
      : "";

  const password =
    typeof body.password === "string"
      ? body.password
      : "";

  if (!name || !isValidEmail(email)) {
    return response(
      request,
      env,
      {
        error: "Nome ou email inválidos.",
      },
      400
    );
  }

  if (password.length < 12) {
    return response(
      request,
      env,
      {
        error:
          "A senha deve possuir pelo menos 12 caracteres.",
      },
      400
    );
  }

  const existingUser = await env.DB.prepare(
    `
    SELECT id
    FROM users
    WHERE LOWER(email) = ?
    LIMIT 1
    `
  )
    .bind(email)
    .first();

  if (existingUser) {
    return response(
      request,
      env,
      {
        error:
          "Já existe um usuário com esse email.",
      },
      409
    );
  }

  const passwordHash =
    await createPasswordHash(password);

  const result = await env.DB.prepare(
    `
    INSERT INTO users (
      name,
      email,
      password_hash,
      role
    )
    VALUES (?, ?, ?, 'admin')
    `
  )
    .bind(
      name,
      email,
      passwordHash
    )
    .run();

  return response(
    request,
    env,
    {
      ok: true,
      user: {
        id: result.meta.last_row_id,
        name,
        email,
        role: "admin",
      },
    },
    201
  );
}

// ============================================================
// LIMPEZA DE SESSÕES EXPIRADAS
// ============================================================

async function cleanupExpiredSessions(env) {
  const now = Math.floor(Date.now() / 1000);

  try {
    await env.DB.prepare(
      `
      DELETE FROM sessions
      WHERE expires_at <= ?
      `
    )
      .bind(now)
      .run();
  } catch {
    // A limpeza não deve impedir uma requisição.
  }
}

// ============================================================
// ROTEADOR PRINCIPAL
// ============================================================

export default {
  async fetch(request, env) {
    try {
      // --------------------------------------------------------
      // OPTIONS / CORS
      // --------------------------------------------------------

      if (request.method === "OPTIONS") {
        return new Response(null, {
          status: 204,
          headers: corsHeaders(request, env),
        });
      }

      const url = new URL(request.url);
      const path = url.pathname;

      // --------------------------------------------------------
      // HOME
      // --------------------------------------------------------

      if (
        path === "/" &&
        request.method === "GET"
      ) {
        return handleRoot(request, env);
      }

      // --------------------------------------------------------
      // LOGIN
      // --------------------------------------------------------

      if (
        path === "/api/login" &&
        request.method === "POST"
      ) {
        return await handleLogin(request, env);
      }

      // --------------------------------------------------------
      // LOGOUT
      // --------------------------------------------------------

      if (
        path === "/api/logout" &&
        request.method === "POST"
      ) {
        return await handleLogout(request, env);
      }

      // --------------------------------------------------------
      // USUÁRIO ATUAL
      // --------------------------------------------------------

      if (
        path === "/api/me" &&
        request.method === "GET"
      ) {
        return await handleMe(request, env);
      }

      // --------------------------------------------------------
      // BOOTSTRAP ADMIN
      // --------------------------------------------------------

      if (
        path === "/api/bootstrap-admin" &&
        request.method === "POST"
      ) {
        return await handleBootstrapAdmin(
          request,
          env
        );
      }

      // --------------------------------------------------------
      // OLIMPÍADAS — LISTAGEM
      // --------------------------------------------------------

      if (
        path === "/api/olympiads" &&
        request.method === "GET"
      ) {
        return await handleListOlympiads(
          request,
          env
        );
      }

      // --------------------------------------------------------
      // OLIMPÍADAS — CRIAÇÃO
      // --------------------------------------------------------

      if (
        path === "/api/olympiads" &&
        request.method === "POST"
      ) {
        return await handleCreateOlympiad(
          request,
          env
        );
      }

      // --------------------------------------------------------
      // OLIMPÍADA ESPECÍFICA
      // --------------------------------------------------------

      const olympiadMatch =
        path.match(
          /^\/api\/olympiads\/(\d+)$/
        );

      if (olympiadMatch) {
        const id = Number(
          olympiadMatch[1]
        );

        if (
          request.method === "GET"
        ) {
          return await handleGetOlympiad(
            request,
            env,
            id
          );
        }

        if (
          request.method === "PUT"
        ) {
          return await handleUpdateOlympiad(
            request,
            env,
            id
          );
        }

        if (
          request.method === "DELETE"
        ) {
          return await handleDeleteOlympiad(
            request,
            env,
            id
          );
        }
      }

      // --------------------------------------------------------
      // LIMPEZA DE SESSÕES
      // --------------------------------------------------------

      await cleanupExpiredSessions(env);

      // --------------------------------------------------------
      // 404
      // --------------------------------------------------------

      return response(
        request,
        env,
        {
          error: "Rota não encontrada.",
        },
        404
      );
    } catch (error) {
      console.error(error);

      return response(
        request,
        env,
        {
          error: "Erro interno do servidor.",
        },
        500
      );
    }
  },
};
