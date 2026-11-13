# ADR 0037 — Recebimento npm experimental

- **Status:** Em implementação isolada; sem publicação ou adapter
- **Data:** 2026-11-08

## Direção

Uma reserva pode ser reivindicada uma vez para receber o tarball previamente limitado e metadados associados. O serviço deve revalidar identidade, autorização, tamanho e digests, inspecionar o archive e seu manifesto, persistir o objeto e verificar leitura integral antes de registrar recibo imutável. A reautorização ocorre na transação final; revogação ou falha deixam a publicação indisponível. Staging é privado e limitado; falhas podem deixar objetos órfãos que não autorizam serving.

O recibo não publica e não implica aprovação, dist-tag, cliente funcional ou completude de backup. Quota deve continuar contando a reserva recebida uma única vez. Recovery parcial deve recusar recibos npm com objeto verificado até existir inventário e restauração completos. Recebimento concorrente, retry, falhas, revogação, quota, staging, SQLite/PostgreSQL e isolamento de storage exigem testes antes da conciliação.

## Evidência parcial

Testes repetidos três vezes com race em SQLite/PostgreSQL exercitaram validação, recebimento concorrente, capacidade, hash, reautorização após revogação, staging e quota. Falha de auditoria em SQLite reverteu o recibo. Filesystem e Floci isolado foram exercitados; readback adulterado foi recusado por uma fixture de storage. Recovery parcial SQLite recusou recibos npm, e o tratamento isolado PostgreSQL preservou o recibo invalidado. Upgrade e rollback v29 preservaram reservas preexistentes nos dois bancos. Build, lint e unitários passaram no worktree; falta gate integral integrado e seguem pendentes revisão, publicação, serving, inventário/restore npm e aceites com cliente real. Floci não comprova atomicidade S3 real.
