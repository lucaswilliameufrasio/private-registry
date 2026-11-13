# ADR 0035 — Credenciais npm de publicação experimentais

- **Status:** Em implementação isolada; não exposta
- **Data:** 2026-11-08

## Escopo e fronteiras

Tokens de escrita npm são capacidades opacas separadas dos tokens pessoais de leitura. Cada credencial pertence a uma pessoa, workspace e repositório npm, vincula-se ao grant de publisher vigente na emissão, expira e é verificável somente pelo digest. Revogar o grant ou desativar o usuário invalida a capacidade; uma nova concessão não reativa o token anterior. A emissão externa deve exigir MFA recente e CSRF, mas esta fatia não habilita rotas nem o adapter.

A autorização de publicação não concede automaticamente permissão para mover dist-tags ou remover versões. Tokens emitidos devem aparecer uma única vez e não ser registrados; somente metadados e verificadores são persistidos. O recovery precisa revogar credenciais, sem reativá-las posteriormente. A custódia do lado do cliente, interoperabilidade com npm real, reservas, revisão e publicação permanecem sem aceite.

## Evidência parcial

Testes focalizados passaram três vezes com race em SQLite e PostgreSQL para emissão vinculada ao grant, limites de validade, isolamento entre usuários e repositórios, recusa de formatos incorretos, segredos incorretos e tokens de leitura, expiração, rollback do callback, revogação, regrant e suspensão. A listagem retorna apenas metadados do proprietário. Um recovery SQLite isolado invalidou a credencial sem alterar a origem. A migration v27 foi testada nos dois bancos para upgrade, rollback por falha e checksum divergente. Faltam gate integral integrado, endpoints com MFA, credenciais operacionais para o cliente e as jornadas npm completas.
