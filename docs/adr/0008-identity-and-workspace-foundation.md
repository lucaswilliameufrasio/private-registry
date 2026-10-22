# ADR 0008 — Identidade e fundação de workspaces

- **Status:** Aceito; bootstrap local está detalhado no ADR 0009 e sessões no ADR 0011; listagem/criação de workspace, gestão limitada de membership, metadados de repositório e gestão de grants estão expostos com autorização HTTP; serving de conteúdo permanece pendente
- **Data:** 2026-10-15

## Contexto

A fase 1 precisa persistir usuários, identidade federada estável, workspaces e membership antes de expor APIs administrativas. Email é mutável e não deve vincular identidades. Participar de um workspace não concede leitura/publicação por padrão. Cadastro de usuário e criação de workspaces são políticas independentes.

## Decisões

- O primeiro administrador será provisionado por operador com acesso ao servidor, por fluxo local de CLI; não haverá endpoint HTTP público de bootstrap nem segredo de bootstrap em argumentos/logs. A conta local inicial e seu hash Argon2id estão detalhados no ADR 0009.
- Usuário é identidade de domínio independente de métodos de login. Identidade externa é única por `(provider_id, issuer, subject)`; email não é chave nem permite auto-link.
- Workspace tem ID opaco UUIDv7, slug lowercase único e imutável e nome de exibição editável.
- Criação de workspace tem política própria: `admin_only`, `authorized_users` ou `any_user`; cadastro permanece separado e fechado por padrão.
- O usuário que cria o workspace torna-se owner. Membros não recebem leitura nem publicação automaticamente; owner/admin podem gerir o workspace e ler seus repositórios, mas publicação exige concessão explícita. O último owner ativo não poderá ser removido ou rebaixado.
- Mudanças de política e criação de workspace geram auditoria na mesma transação. A fase inicial serializa essas mutações no registro singleton da instalação; otimizar granularidade exige medição e preservação de ordenação.
- Operações HTTP protegidas validam a sessão persistida a cada request, aceitam somente estágios `standard`/`mfa` e derivam o ator dessa sessão; sessões `enrollment_only`/`mfa_challenge` não acessam dados protegidos. O serviço interno não é, isoladamente, uma fronteira de autenticação. A API de workspace lista apenas memberships ativos e exige sessão MFA recente para criação. Owners/administradores podem gerir metadados de repositórios; isso não concede autorização de pacote/conteúdo nem é inferido da membership.
- Mutações de membership via HTTP também exigem CSRF/Origin e MFA recente. Owners podem adicionar, reativar, promover, rebaixar e remover membros ativos; administradores só podem conceder/remover o papel `member`, e ninguém pode elevar a própria role. Usuários podem sair, mas a última membership owner ativa não pode ser rebaixada ou removida. Escritas e eventos de auditoria compartilham transação; o lock singleton serializa a verificação de continuidade.

## Consequências e limites

- A migration 000002 instala identidade, políticas de criação, grants para criar workspaces, workspaces, memberships e auditoria em SQLite e PostgreSQL.
- As migrations v2/v7/v8 e os serviços de tenancy/repositórios ainda não implementam passkeys, cadastro/convite, equipes, UI ou sincronização SCIM. A API HTTP lista/cria workspaces, gerencia roles de memberships, configura metadados/visibilidade e administra grants explícitos conforme o ADR 0014; convites não são inferidos da membership. O bootstrap CLI e credencial local ficam definidos separadamente no ADR 0009.
- A persistência e as rotas atuais não provam isolamento de conteúdo servido entre workspaces: há grants e verificações internas, mas ainda faltam adapters/handlers de conteúdo e nenhuma rota serve bytes.
- Alterações sensíveis futuras devem preservar auditabilidade, ownership mínimo, constraints equivalentes entre engines e revogação atual.

## Evidência

- [Plano — identidade e cadastro](../development-plan.md#8-autenticação-humana-e-cadastro)
- [Plano — autorização e privacidade](../development-plan.md#9-autorização-e-privacidade)
- [ADR 0004 — identidade OIDC e SCIM](0004-authentication-and-scim-identity.md)
- [ADR 0007 — migrations](0007-versioned-database-migrations.md)
- [ADR 0009 — bootstrap local e credenciais](0009-local-bootstrap-and-credentials.md)
