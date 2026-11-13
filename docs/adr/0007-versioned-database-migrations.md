# ADR 0007 — Migrations versionadas dos bancos

- **Status:** Aceito para a fundação inicial; gates de upgrade/backup e aceite operacional da v1 continuam pendentes
- **Data:** 2026-10-15

## Contexto

SQLite e PostgreSQL precisam evoluir com schema equivalente, histórico verificável e exclusão mútua. O plano indica Goose e arquivos próprios por dialeto, mas Goose 3.29.0 não registra checksum do conteúdo SQL. SQLite também não tem um lock distribuído que torne segura uma migration concorrente por múltiplos hosts.

## Decisão

- Usar Goose 3.29.0 para interpretar e executar apenas migrations SQL embutidas, em diretórios separados `sqlite/` e `postgres/`. Não aceitar migrations Go nem `NO TRANSACTION` nesta fundação.
- Registrar SHA-256 do conteúdo exato de cada migration em `registry_migration_checksums` antes de executá-la. Rejeitar checksum divergente, versão registrada sem arquivo e histórico aplicado sem checksum verificável.
- Registrar tentativas em `registry_migration_attempts`; sucesso, falha controlada e execução interrompida ficam distinguíveis, sem persistir texto bruto de erro potencialmente sensível.
- Manter lock durante preflight, checksum e execução: advisory session lock no PostgreSQL; `flock` em sidecar ao arquivo SQLite local. Isso atende uma instalação ativa em host local, não multi-host nem filesystem de rede.
- A primeira migration cria o registro singleton da instalação. O ID é UUIDv7 e persiste através de reinícios/restores.
- `registry migrate` é explícito; `registry serve` não aplica upgrade implicitamente. Nenhum rollback é oferecido.

## Consequências e trabalho restante

- Testes devem executar SQLite real e PostgreSQL real, incluindo repetição/idempotência, lock e alteração de migration já registrada.
- Migrations destrutivas continuam bloqueadas até existir gate de backup completo validado, orçamento de espaço/tempo e procedimento de recovery. Intervalo de schema compatível, operador de upgrade e paridade completa também não são aceitos por este ADR.
- O sidecar SQLite depende de filesystem local com semântica `flock`; o requisito de uma instância ativa continua aplicável.

## Evidência

- [Plano de desenvolvimento — SQLite, PostgreSQL e migrations](../development-plan.md#14-sqlite-postgresql-e-migrations)
- [ADR 0001 — driver SQLite](0001-sqlite-driver.md)
