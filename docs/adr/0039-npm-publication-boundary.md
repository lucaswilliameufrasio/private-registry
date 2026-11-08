# ADR 0039 — Publicação npm experimental

- **Status:** Em implementação isolada; sem adapter público
- **Data:** 2026-11-08

## Fronteira

Um recibo npm verificado somente se transforma em versão imutável por transação sob o lock de grants. A transação revalida a credencial, a quota, a aprovação e as revisões correntes, grava a versão e um vínculo imutável com o recibo e audita o resultado. Retry idêntico retorna o mesmo identificador; o vínculo evita contagem dupla de quota. O banco exige correspondência exata entre recibo, pacote e versão.

Esta fatia não disponibiliza rotas ou serving, não move dist-tags e não resolve backup npm ou a jornada com cliente real. Revisão pendente não pode produzir sucesso nativo. Testes devem cobrir autorização, grants revogados, concorrência, rollback, quota, revisão e recovery antes de qualquer habilitação.

## Evidência parcial

Em SQLite, PostgreSQL e Floci isolado, testes focalizados repetidos três vezes com race cobriram revisão pendente, publicação concorrente idempotente, quota de repositório sem contagem dupla, imutabilidade do vínculo e recusa de retry após revogação do publisher. Em SQLite, falha de auditoria reverteu o vínculo. Na fixture PostgreSQL, recovery invalidou tanto o recibo publicado quanto reservas adicionais; isso não constitui restore completo. A migration v31 passou em upgrade e rollback injetado nos dois bancos, três vezes com race. Build, formatação, lint e unitários passaram neste worktree; falta gate integral integrado e permanecem pendentes adapter, dist-tags, serving, recovery integral e jornadas reais.
