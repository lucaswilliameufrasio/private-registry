# Spike 0.3 — snapshot PostgreSQL, dump age e restauração sem origem

**Data:** 04/10/2026

**Estado:** comprovado com PostgreSQL real 18.6 e tools do mesmo major; não é backup completo nem suporte operacional PostgreSQL anunciado.

## Reprodução e isolamento

```sh
GOMAXPROCS=4 make setup-postgres
GOMAXPROCS=4 go test -tags=integration -count=1 -v ./internal/spikes/postgresbackup
GOMAXPROCS=4 make verify
```

Fixture fixada: `postgres:18.6-alpine3.23@sha256:8c80c49c67052d82f9aaf4ee1f1881c8926b445a1cc916892934845eb8c24204`. A mesma imagem fornece servidor, `pg_dump`, `pg_restore` e `psql`. Setup só baixa se ausente; suíte usa `--pull=never`. Para testes offline, carregar imagem e preparar dependências antes. Não implica instalação offline do produto nem distribuição das tools no servidor binário/systemd.

Container próprio, nome aleatório, banco exclusivo por caso, rede `none`, sem portas publicadas ou mounts do host/Docker socket, limites de 2 CPUs/512 MiB e 256 processos. `trust` é exclusivo desta fixture sem rede; não é política de produção. Clientes executam via `docker exec`/socket Unix interno, sem senha em argumentos. Cleanup limitado a 60 segundos remove apenas container/volumes próprios e falha a execução se não conseguir.

Readiness sonda TCP **dentro** do container para distinguir o servidor definitivo do servidor Unix temporário usado pelo entrypoint durante init. O primeiro teste com sondagem apenas Unix reproduziu `database system is shutting down`/`starting up`; as repetições atuais exercitam a correção. Os testes de dados seguem usando socket Unix.

## Contrato experimental

`internal/spikes/postgresbackup` usa processos reais, prazo obrigatório, nomes sintéticos validados e configuração de tools confiável do operador, não entrada de cliente. Não é adapter de produção.

- `pg_dump --format=custom --no-owner --no-acl --no-password` transmite stdout diretamente ao writer age, sem arquivo local completo de plaintext.
- Dump calcula SHA-256 do archive plaintext, impõe limite de bytes, cria ciphertext `O_EXCL`/0600, sincroniza e só devolve recibo após sucesso da tool/age. Erro ou warning remove ciphertext parcial; destino preexistente permanece intacto.
- `pg_dump --version` e `pg_restore --version` devem corresponder ao major esperado do servidor. Foram comprovados servidor/tools 18.6 e rejeição da configuração major 17. Não é matriz de upgrades: majors distintos, releases anteriores e distribuição das tools continuam pendentes.
- Stderr, inclusive warning com exit 0, é fatal; diagnóstico retido é limitado a 4096 bytes. Esse comportamento é testado com harness de subprocesso no nível unitário; dados/DDL/snapshot usam PostgreSQL real.
- Restore autentica **todo** age e valida digest antes de executar `pg_restore`. Decriptar direto no stdin da tool poderia permitir commit antes de detectar corrupção em chunk final.
- Restore usa staging temporário 0600 com limite de bytes; remove plaintext em sucesso/falha. Diretório/volume privado e orçamento de disco precisam ser fornecidos pelo operador. Não há promessa de remoção física segura dos blocos do filesystem.
- `pg_restore --single-transaction --exit-on-error --no-owner --no-acl` roda somente depois da validação completa. O chamador deve fornecer banco vazio isolado, não produção. Não usa `--clean` e não apaga dados preexistentes para abrir espaço.

Warnings/timeouts/erro de cleanup não constituem sucesso, mas podem ocorrer depois de um commit da tool. Destino de verificação deve ser descartável e descartado em falha; não há promessa de exactly-once. O futuro adapter local deve controlar o processo diretamente; matar o cliente `docker exec` não prova encerramento imediato de todo processo remoto. A fixture é encerrada ao final da suíte.

## Consistência comprovada e sequences

Uma conexão abre transação read-only repeatable-read, exporta `pg_export_snapshot()` e permanece aberta. Outra conexão confirma alteração de geração nas tabelas pai/filha e insere uma linha. O banco ativo passa de **128 linhas/geração 1 para 129 linhas/geração 2**. `pg_dump --snapshot=<id>` importa o snapshot anterior.

Após dump criptografado, a transação exportadora termina e o **banco de origem é excluído**. A recuperação é feita a partir do ciphertext em um banco novo vazio. Resultado observado:

- PostgreSQL 18.6, dump custom de **8.206 bytes** nesta execução;
- 128 linhas, geração 1 consistente entre pai/filha, 262.144 bytes de payload;
- chave estrangeira restaurada e sequência de identidade utilizável;
- nenhuma dependência do banco original e nenhum plaintext staging remanescente.

**Sequences não seguem snapshot MVCC.** A expectativa inicial de próximo ID 129 falhou: o resultado real foi 130. A inserção concorrente avançou a sequência original até 129; o dump capturou esse high-water mark embora a linha posterior não esteja no snapshot. O teste agora exige 130, explicitamente. IDs opacos não podem depender de sequência sem gaps nem de reversão de `nextval`; o contrato futuro de restore deve preservar valores seguros, sem prometer sequência congelada no instante do snapshot. Catálogo/schema exige controle separado de DDL concorrente.

## Falhas e limites

Testes contra servidor real incluem:

- cancelamento **durante espera observada em `pg_stat_activity` por lock** de tabela, sem ciphertext válido;
- banco inexistente, snapshot expirado/inexistente, limite de dump, cancelamento prévio, destino existente e major divergente;
- chave incorreta, ciphertext adulterado/truncado, digest divergente, limite de staging, arquivo ausente e cancelamento;
- plaintext autenticado que não é archive PostgreSQL;
- conflito no destino: rollback da restauração inteira, inclusive DDL anterior ao conflito, preservando tabela e linha preexistentes.

Regressão de cancelamento durante consulta de versão: teste unitário com subprocesso reproduziu `pg_dump version: signal: killed` sem causa reconhecível por `errors.Is(context.Canceled)`. A correção preserva também o erro do contexto; o teste falhou sem a correção e passou com ela. Prazos da fixture foram ampliados para acomodar o daemon compartilhado sem depender de máquina dedicada, mantendo limites e cancelamento explícitos.

`GOMAXPROCS=4 make verify` completo passou: build sem CGO, formatação, vet, sintaxe Bash, testes sem cache, integração SQLite/PostgreSQL/Floci três vezes e race detector. `GOPROXY=off GOSUMDB=off GOMAXPROCS=4 go test -tags=integration -count=1 ./...` também passou com imagens/caches preparados. Não é prova de instalação offline do produto.

Não são comprovados PITR, clusters grandes, benchmark de CPU/RSS/RTO, roles/tablespaces/globals, extensões necessárias, DDL concorrente, mudança de major, SQL migrations do produto, quotas/pins/GC ou kit de recuperação. `--no-owner/--no-acl` exige política explícita de proprietário/permissões na instalação restaurada; globals não estão neste dump de um banco. Digest/recibo não é manifest autenticado da instalação.

O roundtrip S3 com Floci foi inicialmente um [spike separado](s3-backup.md). A composição deste dump com upload/restore remoto foi comprovada posteriormente no [spike 0.4](postgres-remote-backup.md), sem origem/ciphertext local e sem anunciar backup completo da instalação. Floci continua a fixture S3 do desenvolvimento; seu gap de conclusão condicional concorrente não foi mascarado nem considerado resolvido.
