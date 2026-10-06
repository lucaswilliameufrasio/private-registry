# Spike 0.11 — ordenação SQL de liberação e revogação

**Data:** 06/10/2026

**Estado:** concorrência entre conexões SQLite reais comprovada. Não resolve commit remoto OCI nem define sozinho a semântica operacional de revogação.

## Reprodução

```sh
GOMAXPROCS=4 go test -tags=integration -count=3 -run '^TestSQLite(Independent|Concurrent)' -v ./internal/spikes/ociprobe
GOMAXPROCS=4 make verify
```

Complementa o [spike 0.10](oci-durable-release.md), reutilizando exatamente o helper transacional de liberação. Duas instâncias `sql.DB`, cada uma com conexão própria, acessam o mesmo arquivo SQLite WAL/FULL/FK. Não usa lock Go para coordenar escritores nem banco in-memory.

## Evidência

Três cenários determinísticos mantêm uma transação de escrita aberta e exercitam a outra conexão com `busy_timeout=0`:

- **Revogação primeiro:** atualização de policy segura o writer lock; liberação na segunda conexão recebe `SQLITE_BUSY` real, sem mudar fase/rotas. Depois do commit de revogação, liberação é inelegível.
- **Liberação primeiro:** fase/rotas são preparadas na primeira transação; leitor WAL na segunda ainda vê `verified` e zero rotas. Escrita de revogação recebe `SQLITE_BUSY`, portanto **não foi reconhecida como concluída**. Após commit da liberação, fase/rota publicada aparecem; nova operação explícita de revogação conclui e impede liberação posterior.
- **Rollback da liberação:** enquanto a primeira transação segura o lock, revogação falha por contenção. Rollback deixa fase/rotas anteriores; revogação pode então concluir. Nenhuma publicação parcial aparece.

Outro teste lança liberação e revogação simultâneas em goroutines/conexões distintas, vinte rodadas por execução, com busy timeout de cinco segundos. Admite apenas os resultados equivalentes à ordem commitada no SQLite: release vencedor com fase/rotas completas, ou revogação vencedora com release inelegível e zero rotas. Depois de ambas concluírem, novo release é sempre negado. Os testes determinísticos cobrem as duas ordens; não se exige que um escalonador aleatório produza ambas.

Isso diferencia alteração solicitada, erro de contenção e alteração efetivamente commitada. Não responder sucesso de revogação enquanto seu UPDATE falhou ou continua sem commit. Operações após resolver a transação anterior são chamadas explícitas do teste, não retry automático que esconda resultado incerto.

## Limites preservados

- Prova somente da transação SQL de estado/alcance, não ordenação de `PUT`/commit no Distribution. A janela do [spike 0.9](oci-commit-revocation.md) continua aberta.
- Conexões independentes no mesmo processo/host, não processos independentes, power-loss, recovery ou multi-host; não PostgreSQL.
- Policy e schema de fixture limitados, sem JWT/RBAC/review/auditoria, outbox/coordenador ou roteamento produtivo.
- Revogar publicação após liberação não exclui conteúdo já publicado nem revoga automaticamente o direito de leitura de outro usuário. Semântica de sessões/leitura em voo precisa de provas próprias.
- Nenhuma garantia de Floci concorrente foi alterada: o gap de conclusão multipart permanece obrigatório contra storage de produção.

Não é ADR de adoção nem aceite completo OCI.

## Verificação

`GOPROXY=off GOSUMDB=off GOMAXPROCS=4 make verify` completo passou: build sem CGO, formatação, vet normal/integration, sintaxe Bash, testes sem cache, integrações reais três vezes e race detector. Tools/imagens/caches preparados não provam instalação offline/egress do produto. Continuação 0.11 posterior ao commit/push `1c9f042`, ainda não commitada.
