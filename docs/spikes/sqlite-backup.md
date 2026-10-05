# Spike 0.1 — SQLite online, criptografia age e restauração local

**Data:** 04/10/2026

**Estado:** experimento local reproduzível aprovado; fase 0 e backup de produção ainda incompletos.

## Pergunta e resultado

O driver sem CGO `modernc.org/sqlite` permite usar a Online Backup API com escritas durante a cópia e recuperar o snapshot criptografado sem copiar o `.db` ativo ignorando WAL?

**Sim, no cenário reproduzido.** O driver expõe `NewBackup`, `Step`, `Remaining`, `PageCount` e `Finish` pela conexão obtida com `database/sql.Conn.Raw`. Essa evidência autoriza continuar avaliando modernc; não comprova escala, consistência entre banco e blobs nem segurança de um backup remoto completo.

Versões fixadas nesta entrega:

| Componente | Versão |
| --- | --- |
| Go mínimo do módulo | 1.26.0 |
| Go usado na execução | 1.27.1 linux/amd64 |
| modernc.org/sqlite | v1.60.1 |
| SQLite observado no driver | 3.53.4 |
| filippo.io/age | v1.3.2 |

## Procedimento

```sh
GOMAXPROCS=4 make verify
GOMAXPROCS=4 make spike-sqlite
```

Implementação isolada em `internal/spikes/sqlitebackup`; comando em `cmd/spikes/sqlitebackup`. O comando gera somente arquivos sintéticos num diretório próprio, restrito, sob `/tmp/opencode`. Nenhuma chave privada é impressa ou persistida; a identidade age é efêmera para o teste e não é um kit de recuperação de produção.

1. Abrir SQLite em arquivo real, WAL, foreign keys e `synchronous=FULL` em cada conexão do pool.
2. Popular 128 registros com dados sintéticos suficientes para várias páginas.
3. Executar backup em passos de oito páginas por conexão exclusiva do pool.
4. Entre passos incompletos, uma goroutine em outra conexão confirma três escritas; leituras também continuam. Handshakes tornam a sobreposição reproduzível, sem depender de timing casual.
5. Finalizar a cópia pela API SQLite e fechar a conexão de destino.
6. Calcular SHA-256 do snapshot, criptografá-lo em streaming para arquivo age e remover o snapshot original.
7. Reler ciphertext, decriptar para novo destino, comparar SHA-256, executar `integrity_check`, `foreign_key_check` e validar os 131 registros restaurados.
8. Limpar apenas o diretório criado pela própria execução.

Os destinos são criados com `O_EXCL` e modo 0600: não sobrescrever arquivo existente. Erros/cancelamento removem destinos parciais após liberação dos recursos. Contexto de snapshot exige deadline; `SQLITE_BUSY`/`SQLITE_LOCKED` são repetidos de forma limitada pelo contexto. O cancelamento é observado entre passos e I/O local, não promete interromper instantaneamente uma chamada nativa em andamento. Escritas podem reiniciar a cópia, portanto progresso não é necessariamente monotônico.

## Evidência registrada

Primeira execução do comando nesta máquina: 20 passos, 134 páginas, zero restantes, três escritas durante a cópia, 131 registros restaurados e integridade `ok`. Snapshot e restore tiveram SHA-256 idêntico. O JSON marca `remote_validated: false`, pois nenhum S3 foi utilizado.

A verificação completa passou: build `CGO_ENABLED=0`, formatação, `go vet`, testes sem cache, integração real repetida três vezes e `go test -race`. Os testes cobrem roundtrip, configuração de duas conexões, escrita/leitura durante cópia, cancelamento/timeout, destino existente, banco fechado, parâmetros inválidos, permissões, chave incorreta, adulteração, truncamento e descarte de plaintext parcial.

Não interpretar a duração desse pequeno fixture como benchmark de capacidade ou RTO. A máquina é compartilhada; desempenho com volume real, starvation por escrita contínua, falta de espaço e contenção precisam de cenários próprios.

## Limitações e próximos passos

- Este experimento é local; roundtrip S3/Floci foi comprovado separadamente no [spike 0.2](s3-backup.md), com origem/snapshot removidos. Nenhum deles é backup completo da instalação.
- Sem inventário de blobs, pins duráveis, coordenação GC/deletes ou OCI: não é backup completo da instalação.
- Sem agendamento/outbox/retries persistentes, orçamento de temporário, verificação prévia de espaço ou retomada após morte do processo.
- Sem kit/chave raiz, rotação de recipients ou verificador externo automático. Não há recuperação real da instalação.
- As escritas são limitadas e coordenadas; ainda não prova comportamento sob carga contínua/starvation ou limites de memória para grandes bancos.
- Não há adapter de domínio, migrations, servidor, autorização ou engine PostgreSQL implementados nesta entrega.

Manter modernc como candidato com evidência positiva; a decisão operacional final exige os cenários restantes do plano. O restante da fase 0 continua aberto, sem mover requisitos da v1 para o roadmap por conveniência.
