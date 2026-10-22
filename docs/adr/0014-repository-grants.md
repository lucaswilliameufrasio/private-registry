# ADR 0014 — Grants aditivos de repositório

- **Status:** Aceito; grants administrativos e verificação interna implementados; serving de conteúdo continua fechado
- **Data:** 2026-10-22

## Contexto

Membership define quem pode colaborar no workspace, mas não deve conceder leitura nem publicação implicitamente. O plano define papéis fixos e aditivos por escopo, delegação restrita e nenhuma elevação automática de owners/administradores para publicar. A revogação de membership precisa invalidar o acesso sem permitir que uma readmissão ressuscite permissões antigas.

## Decisões

- Grants são explícitos, aditivos e limitados ao repositório e a um membro ativo do mesmo workspace. Os papéis fixos são `reader`, `publisher`, `maintainer` e `security`; papéis personalizados e grants por pacote ficam adiados.
- Owners ativos podem conceder e revogar qualquer papel, inclusive conceder papel a si próprios por ação explícita e auditada. Administradores ativos podem conceder/revogar somente `reader` e `publisher`, nunca conceder a si próprios. Administradores da instalação não recebem acesso nem capacidade de gerir grants por esse papel.
- Um papel já concedido não é implícito para owner ou administrador. A consulta de grant exige simultaneamente usuário, membership, workspace, repositório e grant ativos; os handlers futuros de conteúdo devem consultar autorização no request e antes de ler storage.
- Grants ativos são únicos por repositório, usuário e papel. Conceder o mesmo papel ativo é idempotente; após revogação, nova concessão cria novo registro para preservar histórico.
- Remover ou suspender uma membership revoga todos os seus grants ativos na mesma transação, via trigger do banco. O registro mantém `membership_inactive` como motivo. Reativar a membership não restaura grants; o owner ou administrador deve concedê-los novamente.
- Revogações manuais guardam ator, horário e motivo e emitem evento de auditoria. A remoção de membership emite seu evento de auditoria transacional, enquanto os registros dos grants preservam a revogação causada por ela.
- HTTP oferece leitura paginada de grants a owner/administrador e concessão/revogação com CSRF/Origin e MFA recente. Não há endpoint de conteúdo, listagem pública ou serving de bytes nesta fatia.

## Alternativas rejeitadas

- **Conceder leitura por membership:** cria acesso implícito, contrariando negação por padrão.
- **Permitir administradores delegarem `maintainer` ou `security`:** excede a delegação confirmada e amplia operações sensíveis; esses papéis ficam reservados a owners.
- **Manter grants ativos durante a membership inativa:** reativaria acesso antigo ao readmitir o usuário.
- **Conceder publicação implicitamente a owners/administradores:** confunde gestão do workspace com capacidade de publicar e contraria o plano.
- **Expor bytes junto com a API de grants:** misturaria uma nova superfície de conteúdo antes de adapters e testes próprios de isolamento por request.

## Consequências e limites

- Migration v8 registra concessões/revogações e instala a revogação transacional em SQLite e PostgreSQL.
- `internal/repositories` passa a oferecer gestão auditada e verificação de grants em cada chamada, ainda sem integração com storage ou protocolos.
- Os nomes de papéis e limites de delegação devem ser reavaliados antes de implementar capacidades específicas de cada adapter; nenhuma rota pode inferir leitura a partir de `listed`/`unlisted`.

## Referências

- [Plano — autorização e privacidade](../development-plan.md#9-autorização-e-privacidade)
- [ADR 0008 — identidade e fundação de workspaces](0008-identity-and-workspace-foundation.md)
- [ADR 0013 — repositórios e visibilidade](0013-repositories-and-visibility.md)
