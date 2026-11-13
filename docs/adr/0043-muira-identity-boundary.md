# ADR 0043 — Fronteira de identidade Muira

- **Status:** Login opcional disponível por configuração explícita; comprovado apenas contra provedor sintético
- **Data:** 2026-11-09

## Contexto e decisão

Muira é um provedor OIDC opcional; login local permanece disponível e o registry mantém sua própria autorização. A identidade externa é `(provider_id, issuer, subject)`, nunca o e-mail. A primeira fronteira interna resolve apenas vínculo Muira previamente existente para um usuário ativo; não cria conta, concede grants ou emite sessão. Um chamador futuro deve antes verificar assinatura, issuer, audiência, expiração e nonce do `id_token`. Nenhuma rota ou configuração Muira foi habilitada.

O fluxo completo ainda exige Authorization Code com PKCE S256, cliente confidencial, validação RS256/JWKS, estado e nonce de uso único, política de MFA e sessão própria. Não se deve interpretar `amr` ou `auth_time` como MFA recente sem validar sua semântica e a política local. O registro de cliente e o uso de credenciais reais exigem autorização separada; testes devem usar provedor sintético local.

## Evidência e limites

Provas focadas passaram três vezes com race em SQLite e PostgreSQL: vínculo exato resolve usuário ativo, issuer ou subject divergente e usuário suspenso são recusados. Passaram build, formatação, lint, unitários, integrações com `-count=3` e integrações com `-race -count=1`, usando `-timeout=40m` por pacote. A função é interna e não comprova autenticação OIDC, vínculo administrativo ou autorização.

Um verificador interno usa `go-oidc` para discovery e JWKS com cliente HTTP injetado e timeout, restringe assinatura a RS256, exige audiência única exata, nonce e subject UUIDv7, e exige deadline. A prova com provedor HTTPS sintético passou três vezes com race, recusando assinatura adulterada, issuer, audiência, nonce, expiração e subject inválidos. Passaram build, formatação, lint, unitários, integrações com `-count=3` e integrações com `-race -count=1`, usando `-timeout=40m` por pacote. O cliente injetado deve impor a política de rede na integração futura; este verificador não autentica requisições, não valida state/PKCE, não interpreta MFA e não emite sessões.

## Login opcional pelo `serve` (2026-11-11)

`REGISTRY_MUIRA_ENABLED=true` habilita o login; sem ele as rotas não existem e qualquer `REGISTRY_MUIRA_*` isolado é erro de configuração. São obrigatórios `REGISTRY_MUIRA_ISSUER` (origem HTTPS), `REGISTRY_MUIRA_CLIENT_ID`, `REGISTRY_MUIRA_CLIENT_SECRET_FILE` (arquivo privado, mesmas regras das credenciais S3) e `REGISTRY_MUIRA_ALLOWED_NETWORKS`; opcionais `REGISTRY_MUIRA_DNS_SERVER` (necessário para issuer por nome) e `REGISTRY_MUIRA_CA_FILE`. A redirect URI é sempre `<REGISTRY_CANONICAL_ORIGIN>/api/v1/auth/muira/callback` e precisa ser registrada exatamente assim no cliente Muira. Discovery roda uma vez na inicialização pelo cliente de saída restrito; provedor inalcançável ou endpoints fora da origem do issuer impedem o `serve` de subir. O login local continua disponível.

Rotas:

- `GET /api/v1/auth/muira/start` — navegação de topo; gera state, nonce e PKCE S256, sela-os com a chave mestra em cookie `__Host-registry-muira-state` (HttpOnly, Secure, SameSite=Lax, 10 min) e redireciona para o authorize.
- `GET /api/v1/auth/muira/callback` — limpa o cookie antes de decidir, exige o state do cookie, troca o código com `client_secret_post` e `code_verifier`, verifica o `id_token` (RS256, issuer, audiência única, expiração, nonce, `sub` UUIDv7) e responde JSON com `stage`. Erros do provedor não são refletidos.
- `POST`/`DELETE /api/v1/auth/muira/link` — vincula ou desvincula a própria conta; exige sessão, CSRF e MFA local recente. O callback de vínculo exige a mesma sessão MFA que iniciou a tentativa. Conta sem senha local não pode se desvincular.
- `POST /api/v1/admin/muira/users` — administrador da instância pré-autoriza um `sub` Muira, criando uma conta sem senha local e sem nenhum grant.

Decisões:

- **Sem criação automática de conta.** Um usuário Muira autenticado, mas não vinculado nem provisionado, recebe 401 e nenhuma linha é criada. A chave é `(issuer, sub)`; e-mail e papéis do Muira são ignorados.
- **Muira substitui apenas a senha.** Depois do `id_token` válido aplica-se a mesma política local: administradores da instância e owners/administradores de workspace caem no desafio ou no cadastro de MFA local; `amr` não é interpretado. Operações sensíveis continuam exigindo MFA local recente.
- **Sem tokens Muira em repouso.** O registry emite a própria sessão e descarta access/refresh tokens; não há rotação de refresh nem logout no provedor. Suspender a conta local ou remover o vínculo encerra o acesso por Muira no próximo login; sessões já emitidas seguem o ciclo de vida local.
- Uma identidade Muira por conta e uma conta por `sub`.

Evidência: jornadas HTTP contra provedor OIDC sintético em processo (login provisionado, vínculo, desafio MFA do administrador, desvínculo, conta suspensa e recusas de state divergente, cookie ausente/adulterado/de outra tentativa, nonce, audiência, PKCE, código desconhecido ou repetido, erro do provedor e requisição cross-origin) e o `serve` real com e sem opt-in, inclusive recusa de subir com provedor inalcançável; passaram três vezes com race.

Pendente: registrar o cliente no Muira real e validar um login de ponta a ponta (ativação externa, depende do proprietário); página de erro/redirect para uma UI futura (hoje o callback responde JSON); rate limit dedicado no callback; logout federado.
