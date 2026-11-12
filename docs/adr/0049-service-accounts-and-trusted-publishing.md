# ADR 0049 — Contas de serviço e trusted publishing com GitHub Actions

- **Status:** Implementado; provado contra emissor OIDC sintético, não contra o GitHub real
- **Data:** 2026-11-12

## Contexto

Todo token pertencia a uma pessoa, valia no máximo 30 dias e parava de funcionar quando ela perdia o grant. Publicar por CI exigia renovar um segredo à mão, preso a uma conta pessoal. O plano prevê contas de serviço com política própria e trusted publishing do GitHub Actions.

## Decisão

**Contas de serviço** (`/api/v1/workspaces/{w}/service-accounts`): usuários sem nenhum método de login, membros (`member`) de exatamente um workspace e que não podem ser promovidos a administrador nem entrar em outro workspace. Recebem grants pela API de grants de sempre. Owners e administradores do workspace emitem, listam e revogam tokens em nome delas (`.../{id}/tokens`, tipos `read`, `cargo-write`, `npm-write`, `pub-write`, `oci-write`), com CSRF e MFA recente; o que o token pode fazer continua dependendo dos grants da conta. Desativar a conta (`DELETE`) suspende o usuário, o que revoga seus tokens, e revoga seus trusted publishers. Uma conta desativada não volta: crie outra.

**Trusted publishing** (opt-in, `REGISTRY_TRUSTED_PUBLISHING_GITHUB=true`): um manager declara, por repositório, que um repositório do GitHub (`owner/nome`), num `ref` exato ou num prefixo terminado em `*` (por exemplo `refs/tags/v*`) e opcionalmente num `environment`, pode agir como uma conta de serviço do workspace. O workflow obtém um token OIDC do GitHub com audiência igual à origem canônica do registry e chama `POST /api/v1/trusted-publishing/github/exchange` com `token`, `workspace_id` e `repository_id`. O registry valida assinatura (RS256, JWKS do emissor), emissor, audiência única e exata, expiração e `jti`; recusa `pull_request_target`; procura um publisher ativo que case repositório, ref e environment; e devolve um token de escrita do formato do repositório e, se a conta tiver grant `reader`, um de leitura, ambos válidos por 15 minutos.

- O `repository_id` numérico do GitHub é fixado no primeiro uso: um repositório apagado e recriado com o mesmo nome por outra pessoa deixa de casar.
- Cada token do GitHub é trocado uma única vez (`jti` registrado até expirar; troca concorrente tem um só vencedor).
- A conta de serviço precisa estar ativa e ter grant `publisher` no momento da troca.
- A descoberta OIDC acontece na primeira troca, então o registry sobe mesmo sem acesso ao GitHub. A saída segue a política explícita (`REGISTRY_TRUSTED_PUBLISHING_GITHUB_ALLOWED_NETWORKS`, `_DNS_SERVER`, `_CA_FILE`).
- Falhas consomem o orçamento de tentativas por origem dos tokens pessoais.

## Limites

Só GitHub Actions. Tokens estáticos de conta de serviço continuam limitados a 30 dias. O registry não consulta a API do GitHub: confia nas claims assinadas. Os runners precisam ter `permissions: id-token: write`.

## Evidência

HTTP em SQLite: conta criada sem credenciais e não promovível; token estático publicando, listado sem segredo, recusado após revogação; publisher ligado a humano recusado; troca válida publicando; repetição recusada; repositório, branch, ref de PR, `pull_request_target`, audiência, expiração, ausência de `jti`, `repository_id` diferente, tag sem ou com outro environment e assinatura forjada recusados; tag com environment aceita; desativação revogando token e trocas. Serviço em SQLite e PostgreSQL com fixação do ID, troca concorrente e perda do grant. Três repetições com race.
