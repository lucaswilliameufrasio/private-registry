# ADR 0036 — Reservas npm experimentais

- **Status:** Em implementação isolada; sem adapter ou publicação
- **Data:** 2026-11-08

## Fronteira

Após autenticar e validar dados limitados, uma credencial npm de publisher pode reservar identidade de nome/versão e quota por prazo limitado. A reserva não comprova objeto, não concede leitura, não publica, não altera dist-tags e não aprova revisão. O retry só é idêntico quando identidade, tamanho, digests, credencial e ator coincidem; colisões divergentes são recusadas. Reservas expiradas ou canceladas liberam quota, mas seu histórico é imutável. A operação e a revalidação do grant compartilham a transação e o lock existente.

As quotas de workspace devem incluir versões e reservas ativas npm em todas as portas genéricas, Go, Cargo e npm, sem contar duas vezes quando futuramente houver publicação; nenhum vínculo de publicação existe nesta fatia. Recovery isolado invalida reservas para evitar reuso após restauração. A API permanece indisponível e a inspeção e retenção do objeto, revisão, dist-tags, compensação e cliente npm real continuam pendentes. A v28 requer testes em SQLite e PostgreSQL, inclusive concorrência, autorização, quota cruzada, falha transacional, cancelamento e recovery.

## Evidência parcial

SQLite e PostgreSQL passaram três vezes com race para reservas idênticas concorrentes, colisões divergentes, identidade já publicada, autorização, cancelamento, expiração e quota cruzada nas entradas genérica, Go e Cargo. Falhas de auditoria para criação e cancelamento foram injetadas em SQLite e reverteram a transação. O worker persistente de expiração foi testado nos dois bancos, mas ainda não é iniciado pelo servidor. Um recovery SQLite isolado invalidou a reserva e preservou a origem. Upgrade e rollback da v28 foram exercitados nos dois bancos. Falta gate integral integrado e o fluxo completo npm; a reserva não é prova de bytes recebidos nem de publicação.
