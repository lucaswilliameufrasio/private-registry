# ADR 0033 — Formato imutável npm

- **Status:** Em implementação isolada; npm ainda indisponível
- **Data:** 2026-11-08

## Contexto e decisão

Cada repositório possui formato imutável e o catálogo npm não deve ser misturado aos formatos genérico, Go ou Cargo. A constraint atual só admite esses três valores. Acrescentar `npm` por migration forward-only, preservando repositórios, chaves estrangeiras, índices, triggers e histórico existentes. Em SQLite o rebuild usa a conexão privada com pragmas controlados e verificação de foreign keys, sob o mesmo lock de migration; em PostgreSQL a alteração é transacional.

Adicionar o valor ao schema não habilita criação de repositórios npm na API nem define unicidade de versões, autorização, quota, revisão ou publicação. A migração precisa de testes de upgrade com dados e relações dos formatos existentes, rollback/falha, concorrência, verificações nos dois bancos e gate integral antes de integração.

## Evidência parcial

Testes focalizados em SQLite/PostgreSQL passaram três vezes com race para upgrade a partir da v24 preservando referências genéricas, Go e Cargo, configuração de quota/revisão, imutabilidade do formato e rollback por falha injetada. O rebuild SQLite recusa execução sem a conexão dedicada; um subprocesso encerrado dentro da transação preservou dados e permitiu retomar e verificar as migrations. Testes de concorrência e de API que mantém npm indisponível também passaram. Ainda falta o gate integral integrado, catálogo npm, credenciais, quotas, revisão, serving e recovery desse formato.
