# CTC — Comitê Técnico-Científico | IFBA Campus Irecê

Base inicial do site do CTC.

## Estrutura

- `frontend/` — site estático para GitHub Pages
- `worker/` — API futura no Cloudflare Workers
- `database/` — schema e dados iniciais do Cloudflare D1

## Frontend

Abra `frontend/index.html` localmente para testar a interface.

Antes de publicar, altere `frontend/js/config.js` para apontar para a URL real da API quando o Worker estiver pronto.

## Publicação no GitHub Pages

O conteúdo que será publicado deve ser o diretório `frontend/`.

No GitHub:
Settings → Pages → Deploy from a branch → branch `main` → folder `/frontend`.

Se a opção `/frontend` não aparecer na sua conta, podemos usar GitHub Actions; o projeto já foi separado para isso.

## Cloudflare

A API foi preparada para:

- GET público de olimpíadas
- login
- sessão
- criação, edição e exclusão de olimpíadas
- autorização por função
- Cloudflare D1

Ainda não coloque credenciais reais no código público.
