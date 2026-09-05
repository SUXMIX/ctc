const ALLOWED_ORIGIN = "https://suxmix.github.io";

const PBKDF2_ITERATIONS = 150000;
const SESSION_DAYS = 7;

export default {
  async fetch(request, env) {
    try {
      return await handleRequest(request, env);
    } catch (error) {
      console.error(error);

      return json(
        {
          error: "Erro interno do servidor."
        },
        500,
        request
      );
    }
  }
};


// ============================================================
// CONFIGURAÇÃO / CORS
// ============================================================

function getAllowedOrigin(request) {
  const origin = request.headers.get("Origin");

  if (origin === ALLOWED_ORIGIN) {
    return origin;
  }

  return ALLOWED_ORIGIN;
}

function corsHeaders(request) {
  return {
    "Access-Control-Allow-Origin": getAllowedOrigin(request),
    "Access-Control-Allow-Credentials": "true",
    "Access-Control-Allow-Headers": "Content-Type",
    "Access-Control-Allow-Methods": "GET, POST, PUT, DELETE, OPTIONS",
    "Vary": "Origin"
  };
}

function json(data, status = 200, request = null) {
  const headers = {
    "Content-Type": "application/json; charset=utf-8",
    "Cache-Control": "no-store"
  };

  if (request) {
    Object.assign(headers, corsHeaders(request));
  }

  return new Response(JSON.stringify(data), {
    status,
    headers
  });
}


// ============================================================
// REQUEST PRINCIPAL
// ============================================================

async function handleRequest(request, env) {
  if (request.method === "OPTIONS") {
    return new Response(null, {
      status: 204,
      headers: corsHeaders(request)
    });
  }

  const url = new URL(request.url);
  const path = url.pathname;

  // ----------------------------------------------------------
  // Rota inicial
  // ----------------------------------------------------------

  if (path === "/" && request.method === "GET") {
    return json(
      {
        name: "CTC API",
        status: "online"
      },
      200,
      request
    );
  }

  // ----------------------------------------------------------
  // LOGIN
  // ----------------------------------------------------------

  if (path === "/api/login" && request.method === "POST") {
    return login(request, env);
  }

  // ----------------------------------------------------------
  // LOGOUT
  // ----------------------------------------------------------

  if (path === "/api/logout" && request.method === "POST") {
    return logout(request, env);
  }

  // ----------------------------------------------------------
  // USUÁRIO ATUAL
  // ----------------------------------------------------------

  if (path === "/api/me" && request.method === "GET") {
    const session = await getSession(request, env);

    if (!session) {
      return json(
        {
          authenticated: false
        },
        200,
        request
      );
    }

    return json(
      {
        authenticated: true,
        user: {
          id: session.user_id,
          username: session.username,
          role: session.role
        }
      },
      200,
      request
    );
  }

  // ----------------------------------------------------------
  // LISTA DE OLIMPÍADAS
  // ----------------------------------------------------------

  if (path === "/api/olympiads" && request.method === "GET") {
    return listOlympiads(request, env);
  }

  // ----------------------------------------------------------
  // CRIAR OLIMPÍADA
  // ----------------------------------------------------------

  if (path === "/api/olympiads" && request.method === "POST") {
    return createOlympiad(request, env);
  }

  // ----------------------------------------------------------
  // OLIMPÍADA ESPECÍFICA
  // ----------------------------------------------------------

  const olympiadMatch = path.match(/^\/api\/olympiads\/(\d+)$/);

  if (olympiadMatch) {
    const id = Number(olympiadMatch[1]);

    if (request.method === "GET") {
      return getOlympiad(request, env, id);
    }

    if (request.method === "PUT") {
      return updateOlympiad(request, env, id);
    }

    if (request.method === "DELETE") {
      return deleteOlympiad(request, env, id);
    }
  }

  return json(
    {
      error: "Rota não encontrada."
    },
    404,
    request
  );
}


// ============================================================
// AUTENTICAÇÃO
// ============================================================

async function login(request, env) {
  let body;

  try {
    body = await request.json();
  } catch {
    return json(
      {
        error: "JSON inválido."
      },
      400,
      request
    );
  }

  const username = String(body.username || "").trim();
  const password = String(body.password || "");

  if (!username || !password) {
    return json(
      {
        error: "Usuário e senha são obrigatórios."
      },
      400,
      request
    );
  }

  const user = await env.DB
    .prepare(
      `
      SELECT id, username, password_hash, role
      FROM users
      WHERE username = ?
      LIMIT 1
      `
    )
    .bind(username)
    .first();

  if (!user) {
    return json(
      {
        error: "Usuário ou senha inválidos."
      },
      401,
      request
    );
  }

  const validPassword = await verifyPassword(
    password,
    user.password_hash
  );

  if (!validPassword) {
    return json(
      {
        error: "Usuário ou senha inválidos."
      },
      401,
      request
    );
  }

  const token = generateToken();

  const expiresAt = new Date(
    Date.now() + SESSION_DAYS * 24 * 60 * 60 * 1000
  ).toISOString();

  await env.DB
    .prepare(
      `
      INSERT INTO sessions
      (token, user_id, expires_at)
      VALUES (?, ?, ?)
      `
    )
    .bind(token, user.id, expiresAt)
    .run();

  const headers = {
    "Content-Type": "application/json; charset=utf-8",
    "Cache-Control": "no-store",
    "Set-Cookie":
      `ctc_session=${token}; ` +
      `HttpOnly; ` +
      `Secure; ` +
      `SameSite=None; ` +
      `Path=/; ` +
      `Max-Age=${SESSION_DAYS * 24 * 60 * 60}`,
    ...corsHeaders(request)
  };

  return new Response(
    JSON.stringify({
      authenticated: true,
      user: {
        id: user.id,
        username: user.username,
        role: user.role
      }
    }),
    {
      status: 200,
      headers
    }
  );
}


async function logout(request, env) {
  const token = getSessionToken(request);

  if (token) {
    await env.DB
      .prepare(
        `
        DELETE FROM sessions
        WHERE token = ?
        `
      )
      .bind(token)
      .run();
  }

  return new Response(
    JSON.stringify({
      success: true
    }),
    {
      status: 200,
      headers: {
        "Content-Type": "application/json; charset=utf-8",
        "Cache-Control": "no-store",
        "Set-Cookie":
          "ctc_session=; HttpOnly; Secure; SameSite=None; Path=/; Max-Age=0",
        ...corsHeaders(request)
      }
    }
  );
}


// ============================================================
// SESSÕES
// ============================================================

function getSessionToken(request) {
  const cookieHeader = request.headers.get("Cookie") || "";

  const cookies = cookieHeader.split(";");

  for (const cookie of cookies) {
    const [name, ...valueParts] = cookie.trim().split("=");

    if (name === "ctc_session") {
      return valueParts.join("=");
    }
  }

  return null;
}


async function getSession(request, env) {
  const token = getSessionToken(request);

  if (!token) {
    return null;
  }

  const session = await env.DB
    .prepare(
      `
      SELECT
        sessions.user_id,
        sessions.expires_at,
        users.username,
        users.role
      FROM sessions
      INNER JOIN users
        ON users.id = sessions.user_id
      WHERE sessions.token = ?
      LIMIT 1
      `
    )
    .bind(token)
    .first();

  if (!session) {
    return null;
  }

  if (new Date(session.expires_at).getTime() <= Date.now()) {
    await env.DB
      .prepare(
        `
        DELETE FROM sessions
        WHERE token = ?
        `
      )
      .bind(token)
      .run();

    return null;
  }

  return session;
}


async function requireEditor(request, env) {
  const session = await getSession(request, env);

  if (!session) {
    return {
      authorized: false,
      response: json(
        {
          error: "Não autenticado."
        },
        401,
        request
      )
    };
  }

  if (session.role !== "admin" && session.role !== "editor") {
    return {
      authorized: false,
      response: json(
        {
          error: "Você não possui permissão para realizar esta ação."
        },
        403,
        request
      )
    };
  }

  return {
    authorized: true,
    session
  };
}


// ============================================================
// SENHAS
// ============================================================

async function hashPassword(password) {
  const salt = crypto.getRandomValues(new Uint8Array(16));

  const key = await crypto.subtle.importKey(
    "raw",
    new TextEncoder().encode(password),
    {
      name: "PBKDF2"
    },
    false,
    ["deriveBits"]
  );

  const derivedBits = await crypto.subtle.deriveBits(
    {
      name: "PBKDF2",
      salt,
      iterations: PBKDF2_ITERATIONS,
      hash: "SHA-256"
    },
    key,
    256
  );

  const hash = new Uint8Array(derivedBits);

  return `${bytesToHex(salt)}:${bytesToHex(hash)}`;
}


async function verifyPassword(password, storedHash) {
  try {
    const parts = storedHash.split(":");

    if (parts.length !== 2) {
      return false;
    }

    const salt = hexToBytes(parts[0]);
    const expectedHash = hexToBytes(parts[1]);

    const key = await crypto.subtle.importKey(
      "raw",
      new TextEncoder().encode(password),
      {
        name: "PBKDF2"
      },
      false,
      ["deriveBits"]
    );

    const derivedBits = await crypto.subtle.deriveBits(
      {
        name: "PBKDF2",
        salt,
        iterations: PBKDF2_ITERATIONS,
        hash: "SHA-256"
      },
      key,
      256
    );

    const actualHash = new Uint8Array(derivedBits);

    if (actualHash.length !== expectedHash.length) {
      return false;
    }

    let result = 0;

    for (let i = 0; i < actualHash.length; i++) {
      result |= actualHash[i] ^ expectedHash[i];
    }

    return result === 0;
  } catch {
    return false;
  }
}


function bytesToHex(bytes) {
  return Array.from(bytes)
    .map(byte => byte.toString(16).padStart(2, "0"))
    .join("");
}


function hexToBytes(hex) {
  if (hex.length % 2 !== 0) {
    throw new Error("Hex inválido.");
  }

  const bytes = new Uint8Array(hex.length / 2);

  for (let i = 0; i < bytes.length; i++) {
    bytes[i] = parseInt(
      hex.substring(i * 2, i * 2 + 2),
      16
    );
  }

  return bytes;
}


function generateToken() {
  const bytes = crypto.getRandomValues(
    new Uint8Array(32)
  );

  return bytesToHex(bytes);
}


// ============================================================
// OLIMPÍADAS — CONSULTA
// ============================================================

async function listOlympiads(request, env) {
  const url = new URL(request.url);

  const search = url.searchParams.get("search");

  let result;

  if (search) {
    const term = `%${search}%`;

    result = await env.DB
      .prepare(
        `
        SELECT *
        FROM olympiads
        WHERE
          acronym LIKE ?
          OR name LIKE ?
          OR area LIKE ?
          OR modality LIKE ?
        ORDER BY
          registration_deadline ASC,
          name ASC
        `
      )
      .bind(term, term, term, term)
      .all();
  } else {
    result = await env.DB
      .prepare(
        `
        SELECT *
        FROM olympiads
        ORDER BY
          registration_deadline ASC,
          name ASC
        `
      )
      .all();
  }

  return json(
    {
      olympiads: result.results || []
    },
    200,
    request
  );
}


async function getOlympiad(request, env, id) {
  const olympiad = await env.DB
    .prepare(
      `
      SELECT *
      FROM olympiads
      WHERE id = ?
      LIMIT 1
      `
    )
    .bind(id)
    .first();

  if (!olympiad) {
    return json(
      {
        error: "Olimpíada não encontrada."
      },
      404,
      request
    );
  }

  return json(
    {
      olympiad
    },
    200,
    request
  );
}


// ============================================================
// OLIMPÍADAS — CRIAÇÃO
// ============================================================

async function createOlympiad(request, env) {
  const auth = await requireEditor(request, env);

  if (!auth.authorized) {
    return auth.response;
  }

  let body;

  try {
    body = await request.json();
  } catch {
    return json(
      {
        error: "JSON inválido."
      },
      400,
      request
    );
  }

  const data = normalizeOlympiad(body);

  if (!data.acronym || !data.name) {
    return json(
      {
        error: "A sigla e o nome da olimpíada são obrigatórios."
      },
      400,
      request
    );
  }

  const now = new Date().toISOString();

  const result = await env.DB
    .prepare(
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
      now,
      now
    )
    .run();

  const created = await env.DB
    .prepare(
      `
      SELECT *
      FROM olympiads
      WHERE id = ?
      `
    )
    .bind(result.meta.last_row_id)
    .first();

  return json(
    {
      success: true,
      olympiad: created
    },
    201,
    request
  );
}


// ============================================================
// OLIMPÍADAS — ATUALIZAÇÃO
// ============================================================

async function updateOlympiad(request, env, id) {
  const auth = await requireEditor(request, env);

  if (!auth.authorized) {
    return auth.response;
  }

  const existing = await env.DB
    .prepare(
      `
      SELECT id
      FROM olympiads
      WHERE id = ?
      LIMIT 1
      `
    )
    .bind(id)
    .first();

  if (!existing) {
    return json(
      {
        error: "Olimpíada não encontrada."
      },
      404,
      request
    );
  }

  let body;

  try {
    body = await request.json();
  } catch {
    return json(
      {
        error: "JSON inválido."
      },
      400,
      request
    );
  }

  const data = normalizeOlympiad(body);

  if (!data.acronym || !data.name) {
    return json(
      {
        error: "A sigla e o nome da olimpíada são obrigatórios."
      },
      400,
      request
    );
  }

  const now = new Date().toISOString();

  await env.DB
    .prepare(
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
      now,
      id
    )
    .run();

  const updated = await env.DB
    .prepare(
      `
      SELECT *
      FROM olympiads
      WHERE id = ?
      `
    )
    .bind(id)
    .first();

  return json(
    {
      success: true,
      olympiad: updated
    },
    200,
    request
  );
}


// ============================================================
// OLIMPÍADAS — EXCLUSÃO
// ============================================================

async function deleteOlympiad(request, env, id) {
  const auth = await requireEditor(request, env);

  if (!auth.authorized) {
    return auth.response;
  }

  const existing = await env.DB
    .prepare(
      `
      SELECT id
      FROM olympiads
      WHERE id = ?
      LIMIT 1
      `
    )
    .bind(id)
    .first();

  if (!existing) {
    return json(
      {
        error: "Olimpíada não encontrada."
      },
      404,
      request
    );
  }

  await env.DB
    .prepare(
      `
      DELETE FROM olympiads
      WHERE id = ?
      `
    )
    .bind(id)
    .run();

  return json(
    {
      success: true
    },
    200,
    request
  );
}


// ============================================================
// NORMALIZAÇÃO DOS DADOS
// ============================================================

function normalizeOlympiad(body) {
  return {
    acronym: cleanString(body.acronym),
    name: cleanString(body.name),
    area: cleanString(body.area),
    modality: cleanString(body.modality),
    registration_method: cleanString(
      body.registration_method
    ),
    registration_deadline: cleanString(
      body.registration_deadline
    ),
    number_of_phases: normalizeNumber(
      body.number_of_phases
    ),
    phase_1_date: cleanString(body.phase_1_date),
    phase_2_date: cleanString(body.phase_2_date),
    phase_3_date: cleanString(body.phase_3_date),
    phase_4_date: cleanString(body.phase_4_date),
    status: cleanString(body.status),
    extra: cleanString(body.extra)
  };
}


function cleanString(value) {
  if (value === null || value === undefined) {
    return "";
  }

  return String(value).trim();
}


function normalizeNumber(value) {
  if (
    value === null ||
    value === undefined ||
    value === ""
  ) {
    return null;
  }

  const number = Number(value);

  if (!Number.isInteger(number) || number < 0) {
    return null;
  }

  return number;
}
