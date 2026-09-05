# Configuração do backend CTC

## 1. Instalar Wrangler

No computador, dentro de `worker/`:

```bash
npm install
```

Depois:

```bash
npx wrangler login
```

## 2. Criar o banco D1

```bash
npx wrangler d1 create ctc
```

Copie o `database_id` retornado para `wrangler.toml`.

## 3. Criar as tabelas

```bash
npx wrangler d1 execute ctc --remote --file=../database/schema.sql
```

## 4. Inserir dados de teste

```bash
npx wrangler d1 execute ctc --remote --file=../database/seed.sql
```

## 5. Criar o primeiro usuário

O primeiro usuário deve ser criado usando o hash PBKDF2 gerado pelo Worker ou por um pequeno script administrativo que faremos na próxima etapa.

Não coloque uma senha em texto puro no banco.

## 6. Publicar

```bash
npm run deploy
```

Depois copie a URL do Worker para:

`frontend/js/config.js`

## Importante

Antes de usar em produção, vamos revisar:

- CORS
- cookies e domínio
- criação segura do primeiro administrador
- rate limiting do login
- limpeza de sessões expiradas
- política de backup do D1
