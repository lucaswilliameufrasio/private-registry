# ADR 0038 — Revisão humana npm experimental

- **Status:** Em implementação isolada; sem adapter ou publicação
- **Data:** 2026-11-08

## Direção

O recibo verificado não autoriza publicação. Quando a política exige revisão, somente revisor com grant explícito ativo pode decidir, sem autoaprovação. A decisão registra versão da política, grant de revisor e grant do publisher vigente; revogação, troca de política ou alteração de autoridade exige nova verificação no momento da publicação. O histórico é imutável e revogação de membership ou suspensão revoga a capacidade de revisão.

Esta fatia não habilita rotas npm nem serving. Ainda são obrigatórios MFA/CSRF nas operações humanas expostas, publicação transacional, dist-tags autorizadas separadamente, provas com cliente real, backup e recovery completos.

## Evidência parcial

Testes SQLite e PostgreSQL, repetidos três vezes com race, cobriram capacidade explícita, proibição de autoaprovação, retry de aprovação, decisão imutável, revogação e nova concessão do revisor, revisão de política, rejeição definitiva e rollback da auditoria em SQLite. A migration v30 foi testada nos dois bancos para upgrade e rollback; build, lint, unitários e integrações afetadas também passaram no worktree. Falta gate integral integrado, rotas humanas com MFA, consulta operacional para revisão e publicação que revalide os grants e a política na mesma transação.
