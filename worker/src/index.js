const JSON_HEADERS = {
  "Content-Type": "application/json; charset=UTF-8",
};

const PBKDF2_ITERATIONS = 150000;

function json(data, status = 200, extraHeaders = {}) {
  return new Response(JSON.stringify(data), {
    status,
    headers: {
      ...JSON_HEADERS,
      ...extraHeaders,
    },
  });
}

function getOrigin(request) {
  return request.headers.get("Origin");
}

function corsHeaders(request, env) {
  const origin = getOrigin(request);
  const allowedOrigin = env.FRONTEND_ORIGIN;

  const headers = {
    "Access-Control-Allow-Methods": "GET, POST, PUT, DELETE, OPTIONS",
    "Access-Control-Allow-Headers": "Content-Type",
    "Access-Control-Allow-Credentials": "true",
    "Vary": "Origin",
  };

  if (origin && origin === allowedOrigin) {
    headers["Access-Control-Allow-Origin"] = origin;
  }

  return headers;
}

function response(request, env, data, status = 200) {
  return json(data, status, corsHeaders(request, env));
}

function getCookie(request, name) {
  const cookieHeader = request.headers.get("Cookie");

  if (!cookieHeader) return null;

  const cookies = cookieHeader.split(";");

  for (const cookie of cookies) {
    const [key, ...valueParts] = cookie.trim().split("=");

    if (key === name) {
      return valueParts.join("=");
    }
  }

  return null;
}

function generateToken() {
  const bytes = new Uint8Array(32);
  crypto.getRandomValues(bytes);

  return Array.from(bytes)
    .map((byte) => byte.toString(16).padStart(2, "0"))
    .join("");
}

function generateSalt() {
  const bytes = new Uint8Array(16);
  crypto.getRandomValues(bytes);

  return Array.from(bytes)
    .map((byte) => byte.toString(16).padStart(2, "0"))
    .join("");
}

function hexToBytes(hex) {
  const bytes = new Uint8Array(hex.length / 2);

  for (let i = 0; i < bytes.length; i++) {
    bytes[i] = parseInt(hex.substr(i * 2, 2), 16);
  }

  return bytes;
}

function bytesToHex(bytes) {
  return Array.from(new Uint8Array(bytes))
    .map((byte) => byte.toString(16).padStart(2, "0"))
    .join("");
}

async function hashPassword(password, salt) {
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
      salt: encoder.encode(salt),
      iterations: PBKDF2_ITERATIONS,
      hash: "SHA-256",
    },
    keyMaterial,
    256
  );

  return bytesToHex(derivedBits);
}

async function createPasswordHash(password) {
  const salt = generateSalt();
  const hash = await hashPassword(password, salt);

  // Tudo fica dentro da única coluna password_hash.
  return `pbkdf2$${PBKDF2_ITERATIONS}$${salt}$${hash}`;
}

async function verifyPassword(password, storedHash) {
  if (!storedHash) return false;

  const parts = storedHash.split("$");

  if (parts.length !== 4) {
    return false;
  }

  const [algorithm, iterationsString, salt, expectedHash] = parts;

  if (algorithm !== "pbkdf2") {
    return false;
  }

  const iterations = Number(iterationsString);

  if (!Number.isInteger(iterations) || iterations <= 0) {
    return false;
  }

  const actualHash = await hashPassword(password, salt);

  if (actualHash.length !== expectedHash.length) {
    return false;
  }

  let difference = 0;

  for (let i = 0; i < actualHash.length; i++) {
    difference |= actualHash.charCodeAt(i) ^ expectedHash.charCodeAt(i);
  }

  return difference === 0;
}

function sessionCookie(token, maxAge) {
  return [
    `ctc_session=${token}`,
    `Max-Age=${maxAge}`,
    "Path=/",
    "HttpOnly",
    "Secure",
    "SameSite=Lax",
  ].join("; ");
}

function clearSessionCookie() {
  return [
    "ctc_session=",
    "Max-Age=0",
    "Path=/",
    "HttpOnly",
    "Secure",
    "SameSite=Lax",
  ].join("; ");
}

async function getAuthenticatedUser(request, env) {
  const token = getCookie(request, "ctc_session");

  if (!token) {
    return null;
  }

  const session = await env.DB.prepare(
    `
    SELECT
      sessions.id,
      sessions.user_id,
      sessions.expires_at,
      users.name,
      users.email,
      users.role
    FROM sessions
    INNER JOIN users ON users.id = sessions.user_id
    WHERE sessions.id = ?
    LIMIT 1
    `
  )
    .bind(token)
    .first();

  if (!session) {
    return null;
  }

  const now = Math.floor(Date.now() / 1000);

  if (Number(session.expires_at) <= now) {
    await env.DB.prepare(
      "DELETE FROM sessions WHERE id = ?"
    )
      .bind(token)
      .run();

    return null;
  }

  return {
    id: session.user_id,
    name: session.name,
    email: session.email,
    role: session.role,
    sessionToken: token,
  };
}

function requireEditor(user) {
  return user && (user.role === "admin" || user.role === "editor");
}

function requireAdmin(user) {
  return user && user.role === "admin";
}

function normalizeOlympiad(body) {
  return {
    acronym: body.acronym?.trim() || "",
    name: body.name?.trim() || "",
    area: body.area?.trim() || "",
    modality: body.modality?.trim() || "",
    registration_method: body.registration_method?.trim() || "",
    registration_deadline: body.registration_deadline || null,
    number_of_phases:
      body.number_of_phases === null ||
      body.number_of_phases === undefined ||
      body.number_of_phases === ""
        ? null
        : Number(body.number_of_phases),
    phase_1_date: body.phase_1_date || null,
    phase_2_date: body.phase_2_date || null,
    phase_3_date: body.phase_3_date || null,
    phase_4_date: body.phase_4_date || null,
    status: body.status?.trim() || "",
    extra: body.extra?.trim() || "",
  };
}

function validateOlympiad(data) {
  if (!data.acronym) {
    return "O acrônimo é obrigatório.";
  }

  if (!data.name) {
    return "O nome da olimpíada é obrigatório.";
  }

  if (!data.area) {
    return "A área é obrigatória.";
  }

  if (
    data.number_of_phases !== null &&
    (!Number.isInteger(data.number_of_phases) ||
      data.number_of_phases < 1 ||
      data.number_of_phases > 4)
  ) {
    return "O número de fases deve estar entre 1 e 4.";
  }

  return null;
}

async function setupAdmin(request, env) {
  const authorization = request.headers.get("Authorization");

  if (!authorization) {
    return response(
      request,
      env,
      { error: "Não autorizado." },
      401
    );
  }

  const expected = `Bearer ${env.ADMIN_SETUP_TOKEN}`;

  if (authorization !== expected) {
    return response(
      request,
      env,
      { error: "Não autorizado." },
      401
    );
  }

  try {
    const body = await request.json();

    const name = body.name?.trim();
    const email = body.email?.trim().toLowerCase();
    const password = body.password;

    if (!name || !email || !password) {
      return response(
        request,
        env,
        { error: "Nome, e-mail e senha são obrigatórios." },
        400
      );
    }

    if (password.length < 10) {
      return response(
        request,
        env,
        { error: "A senha deve ter pelo menos 10 caracteres." },
        400
      );
    }

    const existingAdmin = await env.DB.prepare(
      "SELECT id FROM users WHERE role = 'admin' LIMIT 1"
    ).first();

    if (existingAdmin) {
      return response(
        request,
        env,
        { error: "O administrador inicial já foi criado." },
        409
      );
    }

    const existingUser = await env.DB.prepare(
      "SELECT id FROM users WHERE email = ? LIMIT 1"
    )
      .bind(email)
      .first();

    if (existingUser) {
      return response(
        request,
        env,
        { error: "Este e-mail já está cadastrado." },
        409
      );
    }

    const passwordHash = await createPasswordHash(password);

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
      .bind(name, email, passwordHash)
      .run();

    return response(
      request,
      env,
      {
        ok: true,
        message: "Administrador criado com sucesso.",
        user_id: result.meta.last_row_id,
      },
      201
    );
  } catch (error) {
    console.error("Admin setup error:", error);

    return response(
      request,
      env,
      { error: "Erro ao criar administrador." },
      500
    );
  }
}

export default {
  async fetch(request, env) {
    
    const url = new URL(request.url);
    const path = url.pathname;

    // CORS preflight
    if (request.method === "OPTIONS") {
      return new Response(null, {
        status: 204,
        headers: corsHeaders(request, env),
      });
    }

    if (path === "/api/setup-admin" &&request.method === "POST") {
    return setupAdmin(request, env);
    }
    
    // Endpoint básico para verificar se o Worker está online.
    if (path === "/" && request.method === "GET") {
      return response(request, env, {
        ok: true,
        service: "CTC API",
      });
    }

    // =========================================================
    // LOGIN
    // =========================================================


    // =========================================================
// BOOTSTRAP DO PRIMEIRO ADMINISTRADOR
// =========================================================

if (
  path === "/api/bootstrap-admin" &&
  request.method === "POST"
) {
  try {
    const bootstrapSecret =
      request.headers.get("X-Bootstrap-Secret");

    if (
      !bootstrapSecret ||
      !env.ADMIN_BOOTSTRAP_SECRET ||
      bootstrapSecret !== env.ADMIN_BOOTSTRAP_SECRET
    ) {
      return response(
        request,
        env,
        { error: "Não autorizado." },
        401
      );
    }

    // A rota só pode ser usada enquanto não existir
    // nenhum administrador.
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
            "O administrador inicial já foi criado. Esta rota está desativada.",
        },
        403
      );
    }

    const body = await request.json();

    const name = body.name?.trim();
    const email = body.email?.trim().toLowerCase();
    const password = body.password;

    if (!name || !email || !password) {
      return response(
        request,
        env,
        {
          error:
            "Nome, e-mail e senha são obrigatórios.",
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

    // Verifica se o e-mail já está cadastrado.
    const existingUser = await env.DB.prepare(
      `
      SELECT id
      FROM users
      WHERE email = ?
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
            "Já existe um usuário com esse e-mail.",
        },
        409
      );
    }

    const passwordHash = await createPasswordHash(password);

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
        message:
          "Administrador criado com sucesso.",
        user: {
          id: result.meta.last_row_id,
          name,
          email,
          role: "admin",
        },
      },
      201
    );
  } catch (error) {
    console.error(
      "Bootstrap admin error:",
      error
    );

    return response(
      request,
      env,
      {
        error:
          "Erro interno ao criar administrador.",
      },
      500
    );
  }
}
    if (path === "/api/login" && request.method === "POST") {
      try {
        const body = await request.json();

        const email = body.email?.trim().toLowerCase();
        const password = body.password;

        if (!email || !password) {
          return response(
            request,
            env,
            { error: "E-mail e senha são obrigatórios." },
            400
          );
        }

        const user = await env.DB.prepare(
          `
          SELECT id, name, email, password_hash, role
          FROM users
          WHERE email = ?
          LIMIT 1
          `
        )
          .bind(email)
          .first();

        if (!user) {
          return response(
            request,
            env,
            { error: "E-mail ou senha inválidos." },
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
            { error: "E-mail ou senha inválidos." },
            401
          );
        }

        // Remove sessões antigas expiradas.
        await env.DB.prepare(
          "DELETE FROM sessions WHERE expires_at <= ?"
        )
          .bind(Math.floor(Date.now() / 1000))
          .run();

        const token = generateToken();

        const sessionDays = Number(env.SESSION_DAYS || 7);
        const expiresAt =
          Math.floor(Date.now() / 1000) +
          sessionDays * 24 * 60 * 60;

        await env.DB.prepare(
          `
          INSERT INTO sessions
            (id, user_id, expires_at)
          VALUES (?, ?, ?)
          `
        )
          .bind(token, user.id, expiresAt)
          .run();

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
          200
        );
      } catch (error) {
        console.error("Login error:", error);

        return response(
          request,
          env,
          { error: "Erro interno ao realizar login." },
          500
        );
      }
    }

    // =========================================================
    // LOGOUT
    // =========================================================

    if (path === "/api/logout" && request.method === "POST") {
      const token = getCookie(request, "ctc_session");

      if (token) {
        await env.DB.prepare(
          "DELETE FROM sessions WHERE id = ?"
        )
          .bind(token)
          .run();
      }

      return new Response(
        JSON.stringify({ ok: true }),
        {
          status: 200,
          headers: {
            ...JSON_HEADERS,
            ...corsHeaders(request, env),
            "Set-Cookie": clearSessionCookie(),
          },
        }
      );
    }

    // =========================================================
    // USUÁRIO ATUAL
    // =========================================================

    if (path === "/api/me" && request.method === "GET") {
      const user = await getAuthenticatedUser(request, env);

      if (!user) {
        return response(
          request,
          env,
          { authenticated: false },
          401
        );
      }

      return response(request, env, {
        authenticated: true,
        user: {
          id: user.id,
          name: user.name,
          email: user.email,
          role: user.role,
        },
      });
    }

    // =========================================================
    // LISTAR OLIMPÍADAS
    // =========================================================

    if (
      path === "/api/olympiads" &&
      request.method === "GET"
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
        ORDER BY registration_deadline IS NULL,
                 registration_deadline ASC,
                 acronym ASC
        `
      ).all();

      return response(request, env, {
        olympiads: result.results || [],
      });
    }

    // =========================================================
    // OLIMPÍADA ESPECÍFICA
    // =========================================================

    const olympiadMatch = path.match(
      /^\/api\/olympiads\/(\d+)$/
    );

    if (olympiadMatch) {
      const id = Number(olympiadMatch[1]);

      // GET
      if (request.method === "GET") {
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
            { error: "Olimpíada não encontrada." },
            404
          );
        }

        return response(request, env, { olympiad });
      }

      // Para modificar uma olimpíada, é necessário login.
      const user = await getAuthenticatedUser(request, env);

      if (!requireEditor(user)) {
        return response(
          request,
          env,
          { error: "Acesso não autorizado." },
          403
        );
      }

      // PUT
      if (request.method === "PUT") {
        try {
          const body = await request.json();
          const data = normalizeOlympiad(body);

          const validationError = validateOlympiad(data);

          if (validationError) {
            return response(
              request,
              env,
              { error: validationError },
              400
            );
          }

          const result = await env.DB.prepare(
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
              updated_at = CURRENT_TIMESTAMP
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
              id
            )
            .run();

          if (!result.meta?.changes) {
            return response(
              request,
              env,
              { error: "Olimpíada não encontrada." },
              404
            );
          }

          const updated = await env.DB.prepare(
            "SELECT * FROM olympiads WHERE id = ?"
          )
            .bind(id)
            .first();

          return response(request, env, {
            ok: true,
            olympiad: updated,
          });
        } catch (error) {
          console.error("Update error:", error);

          return response(
            request,
            env,
            { error: "Erro ao atualizar a olimpíada." },
            500
          );
        }
      }

      // DELETE
      if (request.method === "DELETE") {
        // Somente administrador pode excluir.
        if (!requireAdmin(user)) {
          return response(
            request,
            env,
            {
              error:
                "Somente administradores podem excluir olimpíadas.",
            },
            403
          );
        }

        const result = await env.DB.prepare(
          "DELETE FROM olympiads WHERE id = ?"
        )
          .bind(id)
          .run();

        if (!result.meta?.changes) {
          return response(
            request,
            env,
            { error: "Olimpíada não encontrada." },
            404
          );
        }

        return response(request, env, {
          ok: true,
        });
      }
    }

    // =========================================================
    // CRIAR OLIMPÍADA
    // =========================================================

    if (
      path === "/api/olympiads" &&
      request.method === "POST"
    ) {
      const user = await getAuthenticatedUser(request, env);

      if (!requireEditor(user)) {
        return response(
          request,
          env,
          { error: "Acesso não autorizado." },
          403
        );
      }

      try {
        const body = await request.json();
        const data = normalizeOlympiad(body);

        const validationError = validateOlympiad(data);

        if (validationError) {
          return response(
            request,
            env,
            { error: validationError },
            400
          );
        }

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
            extra
          )
          VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
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
            data.extra
          )
          .run();

        const newId = result.meta.last_row_id;

        const olympiad = await env.DB.prepare(
          "SELECT * FROM olympiads WHERE id = ?"
        )
          .bind(newId)
          .first();

        return response(
          request,
          env,
          {
            ok: true,
            olympiad,
          },
          201
        );
      } catch (error) {
        console.error("Create error:", error);

        return response(
          request,
          env,
          { error: "Erro ao criar a olimpíada." },
          500
        );
      }
    }

    return response(
      request,
      env,
      { error: "Endpoint não encontrado." },
      404
    );
  },
};
