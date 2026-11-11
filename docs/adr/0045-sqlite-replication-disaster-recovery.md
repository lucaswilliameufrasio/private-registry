# ADR 0045 — Disaster recovery do SQLite por replicação contínua

- **Status:** Opt-in (`REGISTRY_REPLICATION_ENABLED=true`); comprovado contra Floci, sem provedor real
- **Data:** 2026-11-11

## Contexto

Não havia nenhum caminho de operador para recuperar o banco depois da perda do host: as peças de backup existentes são bibliotecas internas e marcam todo resultado como `RECOVERY_INCOMPLETE`. O proprietário indicou o `sqlite-replication` para isso. A implementação Go (`sqlite-replication-go`) captura o WAL sob uma lease `BEGIN IMMEDIATE`, publica segmentos LTX num spool local, envia para S3 e restaura uma cadeia verificada sem sobrescrever nada.

## Decisão

Integrar a biblioteca pela API pública, num worker do `serve` (`internal/replication`) e num comando `registry restore-database`.

- **Gerações.** A biblioteca guarda para sempre todos os segmentos incrementais e os reaplica a cada captura; compactação e GC existem, mas não são públicos. Para limitar a cadeia, cada início de processo e cada `REGISTRY_REPLICATION_ROTATE_AFTER_CAPTURES` capturas (default 100) abrem uma geração nova, com snapshot completo e prefixo próprio (`<prefixo>/generations/<timestamp>-<sufixo>`). Gerações antigas só saem do bucket depois que uma mais nova foi enviada por inteiro; ficam as `REGISTRY_REPLICATION_RETAIN_GENERATIONS` mais recentes (default 3, mínimo 2). Objetos que este pacote não nomeou nunca são listados nem apagados.
- **Sem pausa de escrita em processo.** A API exige um write gate; o registry passa um gate vazio, porque a própria captura segura `BEGIN IMMEDIATE` e exclui os escritores no nível do SQLite. Commits que o registry checkpointou entre duas capturas chegam pela reconciliação por imagem da biblioteca. A captura pede o lock sem esperar, então o registry repete por até 15 s enquanto houver `SQLITE_BUSY`. Com replicação ligada, as conexões do registry esperam 30 s (em vez de 5 s) pelo lock antes de falhar.
- **Ciclo.** A cada `REGISTRY_REPLICATION_INTERVAL_SECONDS` (default 30): se banco e WAL não mudaram, nada é feito; senão captura e envia. No shutdown gracioso há uma última tentativa limitada a 30 s, depois que o HTTP parou de aceitar escritas. Três falhas seguidas que não sejam de lock descartam a geração e recomeçam de um snapshot.
- **Destino próprio.** `REGISTRY_REPLICATION_S3_*` é independente do object store (`REGISTRY_S3_*`), com as mesmas regras: endpoint HTTPS, redes explícitas, credenciais em arquivos privados.
- **Restore.** `registry restore-database` exige que o arquivo do banco não exista, tenta a geração mais nova e recua para a anterior se ela estiver incompleta (processo morto antes do primeiro envio), informando quais pulou. A biblioteca verifica a cadeia e roda as checagens do SQLite antes de o arquivo aparecer.

## Correções feitas na biblioteca

A integração expôs dois defeitos, corrigidos em [sqlite-replication-go#1](https://github.com/lucaswilliameufrasio/sqlite-replication-go/pull/1); o `go.mod` aponta para o commit desse branch (`34e5695`) até o merge:

1. Com `pierrec/lz4` v4.1.33 (a versão que o grafo de dependências do registry resolve) a biblioteca não decodificava o próprio snapshot: o `lz4.Reader` passou a procurar um frame seguinte e consumia bytes do cabeçalho de página do LTX.
2. O parser de WAL rejeitava os frames de geração anterior que sobram quando o SQLite reinicia o WAL sem truncar — o que o autocheckpoint padrão faz. A captura falhava em qualquer aplicação que não desligasse o autocheckpoint.

## Limites

- **Só o banco.** Objetos de pacote, chave mestra e configuração não são replicados. O desastre completo só é recuperável com `REGISTRY_STORAGE_DRIVER=s3` (os bytes já estão fora do host) e com cópia da chave mestra guardada pelo operador. Com storage em filesystem, o restore traz um catálogo que aponta para objetos perdidos.
- **RPO.** Perde-se o que foi escrito depois do último ciclo enviado: até o intervalo, ou mais se o destino estiver indisponível. Não há alerta além de log `WARN` por ciclo falho; não existe endpoint de status.
- **Revogações.** Tokens e sessões voltam como estavam no ponto restaurado; o que foi revogado depois precisa ser revogado de novo.
- **Custo por ciclo.** Cada captura copia o banco inteiro (Online Backup) e reaplica a cadeia da geração segurando o lock de escrita, e cada envio reconfirma todos os objetos da geração. Bom para bancos de dezenas ou poucas centenas de MB; bancos grandes vão atrasar escritas e podem estourar os 30 s.
- **Plataforma.** A biblioteca só captura em Linux amd64; em outra plataforma o `serve` recusa subir com replicação ligada. PostgreSQL não é coberto.
- **Provedor.** Apenas Floci foi exercitado. O envio depende de `PutObject` condicional; R2, B2 e S3 reais precisam de validação.
- Um `serve` que falha por falta de banco deixa um arquivo vazio no caminho; é preciso removê-lo antes do `restore-database`, que nunca sobrescreve.
- O `go.mod` depende de um commit de branch ainda não mergeado na biblioteca.

## Evidência

- `internal/replication` (Floci): três escritores concorrentes durante capturas sem nenhuma escrita falhar; checkpoint `TRUNCATE` entre ciclos; ciclo ocioso sem captura nem envio; restore idêntico à origem; escritas posteriores ao último ciclo ausentes do restore; rotação e retenção; restart abrindo geração nova; geração incompleta pulada no restore; objeto alheio preservado na poda; destino indisponível e recuperação. Três repetições com race.
- `cmd/registry`: ensaio de desastre pelos comandos reais — publicação e instalação com npm, `serve` encerrado, diretório de dados removido, `restore-database` (inclusive recusas de sobrescrita), novo `serve` e tarball servido com a integridade publicada, com objetos em S3. Três repetições com race.
- Biblioteca: suíte, `-race` e os testes de regressão novos passando; o teste de reinício de WAL falha em `main`.
