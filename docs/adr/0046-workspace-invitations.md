# ADR 0046 — Convites de workspace e cadastro por convite

- **Status:** Implementado; cadastro aberto continua indisponível
- **Data:** 2026-11-12

## Contexto

O plano define cadastro fechado por padrão, com as opções "somente administradores", "convites" e "aberto", e convites com expiração, escopo, uso único e estado verificável. Até aqui só existiam o administrador do bootstrap e as contas pré-autorizadas via Muira.

## Decisão

- **Política de cadastro:** `GET`/`PUT /api/v1/admin/signup-policy` (administrador da instância; escrita com CSRF e MFA recente) alterna entre `closed` (padrão) e `invitations`. `open` é recusado: o plano exige email verificado e transporte de email, que não existem.
- **Convite:** `POST /api/v1/workspaces/{w}/invitations` com `role` (`member` ou `administrator`) e `ttl_seconds` opcional (padrão 7 dias, máximo 30). Owners convidam os dois papéis; administradores só `member`, como na delegação de membership. O token (`prinv_…`) aparece uma vez; o banco guarda só o SHA-256. `GET` lista metadados e estado (`pending`, `redeemed`, `revoked`, `expired`); `DELETE .../invitations/{id}` revoga. Tudo auditado.
- **Uso:** `POST /api/v1/auth/invitations/redeem` cria uma conta local (mesmas regras de login, nome e senha do bootstrap; Argon2id) e a membership numa só transação, e só com a política `invitations`. Não abre sessão: a pessoa faz login normal, e um convite de administrador leva ao cadastro de TOTP. `POST /api/v1/invitations/accept`, com sessão, adiciona uma conta existente — inclusive as que entram pelo Muira — e não depende da política.
- O convite dá apenas membership. Grants de repositório continuam explícitos.
- Um convite deixa de valer se quem o criou perder o papel que permitia criá-lo, for suspenso, ou se o workspace deixar de estar ativo. Uso concorrente do mesmo convite tem um único vencedor.
- Tentativas de uso compartilham o orçamento por origem dos tokens pessoais; a criação de conta tem no máximo duas derivações Argon2id simultâneas.
- A recuperação isolada revoga convites pendentes restaurados, como faz com tokens.

## Limites

Sem email: o token precisa ser entregue por outro canal. Sem cadastro aberto, sem convite restrito a um email ou login específico (quem tiver o token o usa), sem reset de senha por convite.

## Evidência

Jornada HTTP em SQLite (política fechada recusando, conta criada, reutilização recusada, login de membro e de administrador com TOTP, revogação, listagem sem tokens, aceite por conta existente, já-membro, ausência de grants, convite de administrador rebaixado deixando de valer) e PostgreSQL real com uso concorrente do mesmo convite; três repetições com race.
