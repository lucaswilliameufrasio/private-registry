# ADR 0001 — Driver SQLite do servidor

- **Status:** Aceito para implementação inicial; aceite operacional da v1 continua condicionado aos critérios de validação
- **Data:** 2026-10-12

## Contexto

SQLite é o banco padrão do registry; PostgreSQL é opcional e precisa manter paridade funcional. O servidor deve compilar sem CGO para simplificar binários Linux. O backup SQLite precisa usar snapshot consistente do banco ativo, inclusive com WAL, sem copiar o arquivo `.db` por fora.

O spike 0.1 comprovou `modernc.org/sqlite` com `database/sql`, Online Backup API, escritas confirmadas por outra conexão durante a cópia, criptografia age e restauração com SHA-256, `integrity_check` e `foreign_key_check`. A prova é pequena e não demonstra escala, starvation, parity do produto ou backup completo.

## Decisão

- Adotar `modernc.org/sqlite` como driver SQLite do servidor e manter CGO desabilitado nos builds suportados.
- Usar a Online Backup API do driver para snapshots; não copiar diretamente o banco ativo nem ignorar WAL.
- Manter uma instância ativa por instalação e banco local em volume persistente. Não suportar SQLite em filesystem de rede ou entre hosts.
- Configurar WAL, foreign keys, busy timeout e `synchronous=FULL` em cada conexão, conforme o contrato do plano.
- Tratar PostgreSQL como engine separado, com migrations, queries e testes próprios; este ADR não declara paridade implementada.

## Alternativas consideradas

- **`mattn/go-sqlite3`:** permite SQLite com CGO, mas exige toolchain nativa na cadeia de build/distribuição sem evidência que compense esse custo para o produto.
- **Cópia de arquivo ou leitura direta do `.db`:** rejeitada porque não representa corretamente o estado WAL nem oferece o snapshot concorrente já provado pela API.
- **Adiar a escolha do driver:** rejeitado para iniciar a fundação SQLite; a evidência disponível é suficiente para a escolha inicial, não para declarar capacidade de produção.

## Consequências e trabalho restante

- Dependências, distribuição de binários, migrations e testes passam a usar o driver sem CGO escolhido.
- O adapter deve preservar limites de conexão, transações curtas e tratamento explícito de `SQLITE_BUSY`/`SQLITE_LOCKED`.
- Antes de aceitar a fase de banco, medir restore/backup sob escrita sustentada e volume representativo, validar pressão de disco/temporário e exercitar o adapter de produção.
- Troca de versão do driver exige repetição da matriz de snapshot, WAL, concorrência, cancelamento e restore.
- O suporte PostgreSQL, sua paridade, backup lógico e configuração operacional permanecem decisões/entregas independentes.

## Evidência

- [Spike 0.1 — SQLite online, age e restauração local](../spikes/sqlite-backup.md)
- [Plano de desenvolvimento — SQLite e PostgreSQL](../development-plan.md#14-sqlite-postgresql-e-migrations)
