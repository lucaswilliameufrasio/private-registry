# ADR 0043 — Fronteira de identidade Muira

- **Status:** Preparação interna; autenticação Muira ainda indisponível
- **Data:** 2026-11-09

## Contexto e decisão

Muira é um provedor OIDC opcional; login local permanece disponível e o registry mantém sua própria autorização. A identidade externa é `(provider_id, issuer, subject)`, nunca o e-mail. A primeira fronteira interna resolve apenas vínculo Muira previamente existente para um usuário ativo; não cria conta, concede grants ou emite sessão. Um chamador futuro deve antes verificar assinatura, issuer, audiência, expiração e nonce do `id_token`. Nenhuma rota ou configuração Muira foi habilitada.

O fluxo completo ainda exige Authorization Code com PKCE S256, cliente confidencial, validação RS256/JWKS, estado e nonce de uso único, política de MFA e sessão própria. Não se deve interpretar `amr` ou `auth_time` como MFA recente sem validar sua semântica e a política local. O registro de cliente e o uso de credenciais reais exigem autorização separada; testes devem usar provedor sintético local.

## Evidência e limites

Provas focadas passaram três vezes com race em SQLite e PostgreSQL: vínculo exato resolve usuário ativo, issuer ou subject divergente e usuário suspenso são recusados. Passaram build, formatação, lint, unitários, integrações com `-count=3` e integrações com `-race -count=1`, usando `-timeout=40m` por pacote. A função é interna e não comprova autenticação OIDC, vínculo administrativo ou autorização.
