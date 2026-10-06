# Spike 0.12 — ordenação de liberação/revogação no PostgreSQL

**Data:** 06/10/2026

**Estado:** diferença entre SQLite e PostgreSQL reproduzida; coordenação por linha SQL compartilhada demonstrada em fixture. Não é coordenador produtivo nem solução do commit remoto OCI.

## Reprodução

```sh
GOMAXPROCS=4 make setup-postgres
GOMAXPROCS=4 go test -tags=integration -count=3 -run '^TestPostgresReleaseRevocation' -v ./internal/spikes/postgresbackup
GOMAXPROCS=4 make verify
```

PostgreSQL 18.6 já fixado por digest, fixture própria com network none e limites existentes. Sessões `psql` independentes no servidor real; isolation `read committed` explicitamente verificado. Sem mocks, banco em memória, retry SQL ou novos serviços. Floci continua S3 de desenvolvimento.

## Diferença que impede port ingênuo

No [spike SQLite](oci-release-ordering.md), o writer lock serializava as escritas de policy e tentativa. No PostgreSQL, elas atingem linhas/tabelas distintas. Um `UPDATE attempts … WHERE EXISTS(SELECT … policy)` **não bloqueia a linha de policy** só por lê-la.

O teste deixa a transação de liberação aberta após alterar fase/rotas. Outra sessão revoga e commita policy; sua alteração é confirmada antes de liberar o primeiro COMMIT. Mesmo assim, a liberação original commita `published`/rota. Esse caso caracteriza autorização obsoleta no SQL, não aceite de segurança.

## Coordenação explícita demonstrada

Antes de consultar/effectivar a liberação, a sessão faz `SELECT id FROM policy WHERE id=1 FOR UPDATE` dentro da mesma transação. A revogação atualiza essa mesma linha. Testes:

- Leitor separado não vê fase/rotas da liberação não commitada.
- Revogação tenta atualizar e aparece em `pg_stat_activity` com `wait_event_type='Lock'`. O teste observa o servidor; não assume bloqueio por um sleep arbitrário.
- Commit da liberação torna rota/fase visíveis e libera a revogação para commitar depois.
- Rollback da liberação não deixa rota/fase parcial e também libera a revogação.
- Revogação commitada primeiro impede publicação/rota.
- Nova tentativa após revogação concluída permanece `verified` com zero rotas, inclusive quando havia publicação anterior.

O teste de lock falhou ao substituir `FOR UPDATE` por leitura normal: `revocation completed without waiting for shared policy lock`. Lock restaurado antes da verificação.

Espera por lock é operação **ainda não concluída**, não acknowledgment de revogação. Essa distinção é necessária para interpretar a ordem SQL; não fixa por si só o contrato/latência de API do produto.

## Limites ainda obrigatórios

- Uma linha de policy e schema sintético, sem RBAC composto, reviewers/auditoria/outbox ou adapter de produção. Mudanças em outras linhas de permissão não se tornam protegidas automaticamente.
- Port produtivo deve escolher recursos/ordem de locks, isolamento e tratamento de deadlocks/timeouts/rollback; não copiar um lock singleton global que bloqueie toda a instalação.
- Não mede latência em carga, não demonstra sessões em hosts distintos, crash/failover, nem coordenação SQL/blob/OCI/GC completa.
- Prova somente da liberação SQL. Não segura ou cancela commit remoto no Distribution; a corrida [0.9](oci-commit-revocation.md) continua aberta.
- Os manifests/blobs continuam verdade do motor, e material rejeitado/pending continua precisando de quotas/leases/pins/reconciliação/GC.

Não conclui aceite OCI, suporte de produção PostgreSQL ou decisão arquitetural definitiva.

## Verificação

`GOPROXY=off GOSUMDB=off GOMAXPROCS=4 make verify` completo passou: build sem CGO, formatação, vet normal/integration, sintaxe Bash, testes sem cache, integrações reais três vezes e race detector. Tools/imagens/caches preparados não provam instalação offline/egress do produto. Continuação 0.12 posterior ao commit/push `c1916d7`, ainda não commitada.
