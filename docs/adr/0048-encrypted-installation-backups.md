# ADR 0048 — Backups completos cifrados, verificação e restauração

- **Status:** Implementado; agendamento e verificador em host separado ficam com o operador
- **Data:** 2026-11-12

## Contexto

A replicação do ADR 0045 cobre só o banco SQLite, só o último estado e depende do object store de produção. O plano exige backup independente do bucket de produção, cifrado, com verificação e restauração sem a origem, também para PostgreSQL.

## Decisão

Três comandos, configurados por `REGISTRY_BACKUP_S3_*` (mesmas regras de destino S3), `REGISTRY_BACKUP_AGE_RECIPIENT` (chave pública age X25519) e `REGISTRY_BACKUP_RETAIN` (padrão 7):

- **`registry backup`** roda com o servidor no ar. SQLite: cópia pela Online Backup API. PostgreSQL: `pg_dump --format=custom` sobre um snapshot exportado (`pg_export_snapshot`), com a lista de objetos lida na mesma transação — o dump e os objetos copiados correspondem ao mesmo instante. As ferramentas precisam ter o mesmo major do servidor (conferido antes) e recebem a conexão por variáveis libpq, nunca na linha de comando. Envia ao bucket de backup cada objeto que o banco exige (publicados e uploads já verificados) e que o bucket ainda não tem, cifrado com age; depois o dump cifrado; por último `manifest.json` (ID, instalação, schema, SHA-256 e tamanho do dump, lista de objetos). Um backup sem manifest é incompleto. Aplica retenção: mantém os N mais recentes, remove incompletos com mais de um dia e objetos que nenhum manifest mantido lista.
- **`registry verify-backup --identity FILE [--id ID]`** baixa e decifra (o age autentica cada bloco), confere digest e tamanho contra o manifest, roda `integrity_check` e `foreign_key_check` no SQLite (ou `pg_restore --list` no PostgreSQL), confere que o banco só referencia objetos presentes no backup e decifra e confere o SHA-256 de cada objeto. Não toca na instalação; pode rodar em outro host, só com o bucket e a identidade.
- **`registry restore-backup --identity FILE [--id ID]`** exige destino vazio (arquivo SQLite inexistente ou banco PostgreSQL sem tabelas) e o lock de instância livre. Restaura os objetos no storage configurado primeiro e o banco por último (SQLite por link de um arquivo já verificado; PostgreSQL com `pg_restore --single-transaction --exit-on-error`), para que o banco nunca nomeie um objeto ausente.

A instalação nunca tem a identidade: o servidor não consegue ler os próprios backups, e o vazamento do bucket não expõe pacotes. Arquivos de identidade precisam ser privados.

## Limites

- **Não inclui** chave mestra, arquivos de segredo nem configuração. Sem a chave mestra, segredos de TOTP não podem ser abertos: guarde-a separadamente.
- **Credenciais voltam como estavam** no backup; revogue de novo o que foi revogado depois.
- **Agendamento** é do operador (cron/systemd timer). Não há alerta de falha além do código de saída e dos logs.
- **Um executor por bucket**: dois `backup` simultâneos no mesmo destino podem interferir na retenção.
- A coleta offline de objetos (ADR 0047) não deve rodar ao mesmo tempo que um backup: ela apaga objetos que o backup em curso pode tentar ler, e o backup falha (não fica corrompido).
- `pg_dump`/`pg_restore` acessam o banco por fora da política de saída do registry; conexões TCP dependem da configuração do próprio libpq. DSNs com aspas não são aceitos (use DSN em URL).
- Objetos são lidos inteiros em memória na verificação e na restauração (até 1 GiB por objeto).
- Apenas Floci foi exercitado como bucket.

## Evidência

`internal/fullbackup`: SQLite (dois backups com o segundo sem reenvio de objetos, tudo cifrado no bucket, verificação do mais recente e de um específico, identidade errada recusada, staging limpo, restauração idêntica, recusa de sobrescrita, retenção, objeto adulterado detectado) e PostgreSQL real com `pg_dump`/`pg_restore` 18.6 (backup, verificação, restauração em banco novo com o mesmo ID de instalação e schema verificado, recusa em banco não vazio). `cmd/registry`: publicação npm, `backup`, `verify-backup` (inclusive recusa de identidade legível por outros), remoção de todo o diretório de dados, `restore-backup`, recusa de repetir e de restaurar com o servidor no ar, e o pacote servido com a integridade original. Três repetições com race.
