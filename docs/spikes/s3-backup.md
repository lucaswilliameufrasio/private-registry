# Spike 0.2 — criptografia antes do upload e restore S3/Floci

**Data:** 04/10/2026

**Estado:** roundtrip comprovado contra emulador; atomicidade concorrente não comprovada. Sem backup completo, release ou conclusão da fase 0.

## Pergunta e resultado

Conseguimos criptografar um snapshot antes de enviá-lo, publicar um objeto multipart e restaurar via S3 sem depender do banco ou snapshot locais?

**Sim, contra Floci isolado.** A integração cria banco SQLite com WAL/FULL/foreign keys, usa a Online Backup API, calcula digest independente, transmite ciphertext age ao S3, fecha/remove origem e snapshot e baixa o objeto para novo destino. O resultado passa em SHA-256, `integrity_check`, `foreign_key_check` e conteúdo esperado.

Floci substituiu MinIO por decisão do usuário. A evidência anterior com MinIO é histórica; o setup e os testes atuais não dependem dele. Floci é um emulador AWS executado de verdade, não mock do cliente, e não comprova todas as garantias de um backend S3 de produção. Cliente e servidor estão nesta máquina; isso não prova disaster recovery multi-host.

## Dependências e reprodução

| Componente | Versão/fonte fixada |
| --- | --- |
| AWS SDK Go v2 core | v1.47.1 |
| AWS SDK Go v2 S3 | v1.114.0 |
| AWS SDK Go v2 credentials | v1.20.6 |
| Floci desenvolvimento | 2.1.0 |
| Imagem | floci/floci:2.1.0 |
| Digest | sha256:f5aa8c18302cedb4f2385f5c4e455b3efc77fee6bf7b6e5d1712b2817ba102db |

Age/SQLite/Go permanecem conforme [spike 0.1](sqlite-backup.md). Referências: [release Floci](https://github.com/floci-io/floci/releases/tag/2.1.0) e [S3 na versão testada](https://github.com/floci-io/floci/blob/2.1.0/docs/services/s3.md).

```sh
GOMAXPROCS=4 make setup-floci
GOMAXPROCS=4 make verify
GOMAXPROCS=4 go test -tags=integration -count=1 -v ./internal/spikes/remotebackup
```

Setup inspeciona a imagem fixada e só faz pull quando ausente. A suíte usa `--pull=never`; preparar imagem via `docker load` e dependências Go para desenvolvimento offline. Ausência de Docker/imagem falha, sem skip. Isso não prova instalação offline do produto.

Cada suíte inicia container próprio com nome aleatório, porta dinâmica publicada apenas em `127.0.0.1`, sem mounts do host/Docker socket, com 2 CPUs/512 MiB, usuário 1001, capabilities removidas e `no-new-privileges`. Os dados são exclusivos do container. Health é `/health`. Credenciais locais são `test/test`, suportadas explicitamente pelo Floci; não são segredos cloud. `LOCALSTACK_PARITY=false` e `FLOCI_SERVICES_S3_ENFORCE_AUTH=true` ativam a verificação SigV4 sem overrides de compatibilidade. A rejeição de segredo incorreto é testada. Floci documenta limitações como ausência de validação das assinaturas por chunk de aws-chunked.

Não há configuração de notificações/cloud. Isso não é sandbox de rede deny-by-default: a rede Docker padrão ainda pode sair, e o contrato de egress do produto continua pendente. Cada caso usa bucket próprio; três repetições exercitam o mesmo emulador com dados anteriores presentes. Cleanup remove apenas container/volumes da suíte e falha a execução se não conseguir removê-los.

## Mecanismo experimental

- Cliente S3 real AWS SDK Go v2, credenciais explícitas, path-style e endpoint literal de loopback; sem busca de credenciais cloud.
- Produtor age ligado a `io.Pipe`; sem arquivo local completo de ciphertext.
- Multipart reutiliza um buffer de 5 MiB, uma parte por vez; age/I/O possuem buffers adicionais. Propriedade estrutural, não benchmark RSS.
- `CompleteMultipartUpload` somente após confirmação de sucesso do produtor; EOF isolado não basta.
- Conclusão com `If-None-Match: *`: rejeição sequencial comprovada; concorrência tem gap descrito abaixo.
- Falha/cancelamento tenta abortar multipart com contexto separado de cinco segundos; falha do abort é retornada. Reconciliação persistente ainda não existe.
- Restore faz GET novo, autentica age, limita plaintext e verifica SHA-256 independente. Destino `O_EXCL`/0600 é sincronizado; parcial removido em falha, nunca arquivo preexistente.
- ETag multipart não é usado como SHA-256. Digest retornado é do plaintext; no teste SQLite é comparado ao calculado antes do upload.

## Evidência e falhas

Fixture SQLite: **28.672 bytes plaintext, 28.872 ciphertext, uma parte**; banco, snapshot e sidecars removidos, digest/integridade/foreign keys válidos. Fixture de mais de 10 MiB transmite três partes e restaura corretamente.

Casos exercitados: multipart; cancelamento/erro após primeira parte sem objeto distribuído nem partes pendentes; sobrescrita sequencial rejeitada; falha age incluindo `UnexpectedEOF`; credenciais erradas; fonte/objeto ausente; endpoint indisponível; corrupção/truncamento; chave incorreta; SHA-256 divergente; limite de plaintext; cancelamento; destino preexistente; endpoint não loopback/credenciais implícitas rejeitados.

Verificação completa passou também com `GOPROXY=off GOSUMDB=off GOMAXPROCS=4 make verify`: build sem CGO, formatação, vet, sintaxe Bash, testes, integração três vezes e race detector. Imagem e dependências estavam previamente preparadas; isso não é isolamento de egress nem instalação offline do produto. O timeout de cleanup foi ajustado para 60 segundos após o daemon compartilhado ultrapassar 15 segundos; cleanup continua limitado e falha o comando se não concluir.

### Gap reproduzido: conclusão concorrente condicional

O primeiro teste de duas conclusões concorrentes exigia exatamente um vencedor. **Falhou: Floci 2.1.0 retornou sucesso para ambos.** Outras repetições tiveram um vencedor e um `412 PreconditionFailed`. Isso é uma corrida do emulador: proteção sequencial não comprova exclusão atômica.

`TestFlociConcurrentConditionalCompletionProbe` caracteriza essa capacidade: sincroniza dois uploads antes da conclusão, aceita um ou dois sucessos, exige que rejeições sejam `PreconditionFailed`, verifica restauração e ausência de partes abandonadas, e registra que atomicidade não está estabelecida. Não é teste de aceitação da invariável de produção. Não foi adicionado lock local para esconder a limitação. Antes de produção, executar aceitação estrita de exatamente um vencedor contra backend S3 real e validar concorrência entre processos. Continua obrigatório na v1, não no roadmap de adiamentos.

## Limitações e próximo contrato

Recibo experimental não é manifest autenticado completo, marcador de conclusão da instalação, kit de recuperação ou relatório do verificador externo. Faltam inventário de blobs/OCI, pins/GC, quota/reserva, retries persistentes, cron, restauração de configuração e revogação. Timeout na conclusão pode ter resultado ambíguo; exige reconciliação futura, não promessa exactly-once.

Não comprovados R2/AWS/outros backends, atomicidade concorrente, morte do processo, retenção/prune, grandes volumes/RSS, TLS operacional ou egress deny-by-default. Próximos contratos: PostgreSQL `pg_dump`/`pg_restore`, OCI, Hex, Authentik/SCIM e backup completo/verificador isolado.
