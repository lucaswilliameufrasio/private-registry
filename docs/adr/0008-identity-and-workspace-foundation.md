# ADR 0008 — Identidade e fundação de workspaces

- **Status:** Aceito para a fundação; login, bootstrap e autorização de conteúdo continuam pendentes
- **Data:** 2026-10-15

## Contexto

A fase 1 precisa persistir usuários, identidade federada estável, workspaces e membership antes de expor APIs administrativas. Email é mutável e não deve vincular identidades. Participar de um workspace não concede leitura/publicação por padrão. Cadastro de usuário e criação de workspaces são políticas independentes.

## Decisões

- O primeiro administrador será provisionado por operador com acesso ao servidor, por fluxo local de CLI; não haverá endpoint HTTP público de bootstrap nem segredo de bootstrap em argumentos/logs. Credencial, MFA e recuperação serão definidos e implementados com o fluxo local de conta em uma fatia posterior.
- Usuário é identidade de domínio independente de métodos de login. Identidade externa é única por `(provider_id, issuer, subject)`; email não é chave nem permite auto-link.
- Workspace tem ID opaco UUIDv7, slug lowercase único e imutável e nome de exibição editável.
- Criação de workspace tem política própria: `admin_only`, `authorized_users` ou `any_user`; cadastro permanece separado e fechado por padrão.
- O usuário que cria o workspace torna-se owner. Membros não recebem leitura nem publicação automaticamente; owner/admin podem gerir o workspace e ler seus repositórios, mas publicação exige concessão explícita. O último owner ativo não poderá ser removido ou rebaixado.
- Mudanças de política e criação de workspace geram auditoria na mesma transação. A fase inicial serializa essas mutações no registro singleton da instalação; otimizar granularidade exige medição e preservação de ordenação.
- Não expor operações HTTP até haver principal autenticado e autorização no servidor. O serviço interno não é, isoladamente, uma fronteira de autenticação.

## Consequências e limites

- A migration 000002 instala identidade, políticas de criação, grants para criar workspaces, workspaces, memberships e auditoria em SQLite e PostgreSQL.
- Esta fatia não implementa senha, sessão, passkey/TOTP, bootstrap CLI, cadastro/convite, equipes, grants de conteúdo, API/UI ou sincronização SCIM.
- A persistência não prova ainda o isolamento de conteúdo entre dois workspaces; isso depende de grants, repositórios, handlers e testes de autorização antes de servir pacotes.
- Alterações sensíveis futuras devem preservar auditabilidade, ownership mínimo, constraints equivalentes entre engines e revogação atual.

## Evidência

- [Plano — identidade e cadastro](../development-plan.md#8-autenticação-humana-e-cadastro)
- [Plano — autorização e privacidade](../development-plan.md#9-autorização-e-privacidade)
- [ADR 0004 — identidade OIDC e SCIM](0004-authentication-and-scim-identity.md)
- [ADR 0007 — migrations](0007-versioned-database-migrations.md)
