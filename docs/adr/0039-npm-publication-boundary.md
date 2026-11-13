# ADR 0039 — Publicação npm experimental

- **Status:** Em implementação isolada; sem adapter público
- **Data:** 2026-11-08

## Fronteira

Um recibo npm verificado somente se transforma em versão imutável por transação sob o lock de grants. A transação revalida a credencial, a quota, a aprovação e as revisões correntes, grava a versão e um vínculo imutável com o recibo e audita o resultado. Retry idêntico retorna o mesmo identificador; o vínculo evita contagem dupla de quota. O banco exige correspondência exata entre recibo, pacote e versão.

Esta fatia não disponibiliza rotas ou serving, não move dist-tags e não resolve backup npm ou a jornada com cliente real. Revisão pendente não pode produzir sucesso nativo. Testes devem cobrir autorização, grants revogados, concorrência, rollback, quota, revisão e recovery antes de qualquer habilitação.

## Evidência parcial

Em SQLite, PostgreSQL e Floci isolado, testes focalizados repetidos três vezes com race cobriram revisão pendente, publicação concorrente idempotente, quota de repositório sem contagem dupla, imutabilidade do vínculo e recusa de retry após revogação do publisher. Em SQLite, falha de auditoria reverteu o vínculo. Na fixture PostgreSQL, recovery invalidou tanto o recibo publicado quanto reservas adicionais; isso não constitui restore completo. A migration v31 passou em upgrade e rollback injetado nos dois bancos, três vezes com race. Build, formatação, lint e unitários passaram neste worktree; falta gate integral integrado e permanecem pendentes adapter, dist-tags, serving, recovery integral e jornadas reais.

## Composição experimental no servidor

`REGISTRY_EXPERIMENTAL_NPM=true` habilita explicitamente as rotas npm no `serve`, com filesystem local e staging privado em `npm-staging`; o padrão é `false`, e valores diferentes de `true` ou `false` são recusados. O arquivo comprimido é limitado pelo menor entre `REGISTRY_MAX_UPLOAD_BYTES` e 64 MiB; a concorrência usa o menor entre `REGISTRY_MAX_CONCURRENT_UPLOADS` e 16. O documento de publicação tem limite de 128 MiB; conteúdo descomprimido tem limite de 512 MiB, com até 10.000 entradas e manifesto de 1 MiB. O `serve` não executa migrations.

Uma prova do processo `serve` passou três vezes com race, verificando rota ausente por padrão e recusa sem credencial quando habilitada. Passaram build, formatação, lint, unitários, integrações com `-count=3` e integrações com `-race -count=1`, usando `-timeout=40m` por pacote. Não prova publicação pelo processo real, recuperação integral ou cleanup após crash.

Uma prova adicional passou três vezes com race usando npm real através do `serve` e proxy TLS local: publicou um pacote, verificou o catálogo SQLite e instalou os bytes esperados. Usuário, grants e tokens foram preparados diretamente por serviços e SQL de fixture; não comprova jornada administrativa completa, recovery integral ou cleanup após crash. Passaram build, formatação, lint, unitários, integrações com `-count=3` e integrações com `-race -count=1`, usando `-timeout=40m` por pacote.
