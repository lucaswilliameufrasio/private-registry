# Spike 0.16 — verificador externo de backup PostgreSQL remoto

**Data:** 09/10/2026

**Estado:** prova local de um logical dump PostgreSQL → age → Floci; verificação GET/restore em subprocesso distinto. Não é backup completo nem verificador operacional.

## Reprodução

```sh
GOMAXPROCS=4 go test -tags=integration -count=3 -run '^TestExternalPostgresRemoteRecoveryWithoutOriginOrProducerCiphertext$' -v ./internal/spikes/postgresbackup
GOPROXY=off GOSUMDB=off GOMAXPROCS=4 make verify
```

Usa PostgreSQL 18.6 e Floci 2.1.0 fixados por digest, ferramentas `pg_dump`/`pg_restore` do mesmo major, AWS SDK S3 real, age e PostgreSQL reais. Fixtures próprias; credenciais S3 `test/test`; bucket e containers da execução isolados e removidos pela fixture. PostgreSQL roda em container `--network=none`, 2 CPUs/512 MiB. Floci publica porta dinâmica em loopback e é limitado a 2 CPUs/512 MiB. Sem MinIO, cloud real, bucket compartilhado ou fallback para integração mockada.

## Fluxo exercitado

1. Produtor em subprocesso recebe apenas recipient age público e chave Ed25519 de assinatura; não recebe a identidade privada age. `pg_dump` produz um archive custom e transmite plaintext diretamente para age.
2. Receipt versionado/contextualizado declara engine `postgresql`, major das tools, instalação, backup ID, SHA-256/tamanho plaintext e ciphertext. Assinatura Ed25519 usa domínio próprio de PostgreSQL. Trust key não integra o envelope.
3. Produtor envia ciphertext ao objeto S3 e receipt ao objeto separado por último, ambos com `If-None-Match: *`. Remove ciphertext local; o diretório de staging fica vazio. A origem PostgreSQL ainda existe durante a geração, sendo removida pelo controlador antes de iniciar o verificador.
4. Verificador em outro PID carrega trust config local, checa major esperado e baixa primeiro o receipt. Valida assinatura, schema/canonical encoding, instalação, backup ID, engine e major **antes de baixar o dump**.
5. Faz GET do ciphertext remoto para arquivo 0600 sob diretório privado, limita a 34 MiB, confere tamanho e digest assinados. `Restore` autentica todos os chunks age e SHA-256 plaintext antes de executar `pg_restore --single-transaction --exit-on-error` em database nova e descartável.
6. Confirma 128 linhas e 262144 bytes de payload, referências de owner, foreign key, conteúdo esperado e sequência avançando para ID 129. Remove dump plaintext staging, database descartável e ciphertext temporário antes de emitir JSON de sucesso.

O verificador usa o PostgreSQL da fixture via `docker exec`; não restaura no database de origem. PIDs do produtor/verificador/controlador são distintos. A chave privada age só chega ao verificador via stdin; assinatura/trust configuration são separadas dela. O JSON de resultado **não é assinado nem autenticado**.

## Falhas exercitadas

- Receipt alterado, unsigned, malformado ou acima de 8 KiB; chave não confiada; instalação, ID de backup ou major esperado divergente.
- Receipt ou ciphertext remoto ausente.
- Ciphertext de mesmo tamanho com digest divergente; objeto acima do tamanho assinado.
- Ciphertext alterado/truncado com tamanho, digest e receipt legitimamente atualizados pelo signer da fixture: o vínculo passa e age rejeita antes de `pg_restore`.
- Archive plaintext que não é um custom dump PostgreSQL, dentro de envelope age válido e receipt assinado corretamente: `pg_restore` rejeita e database descartável é removida.
- Unit tests rejeitam domínio errado, major/engine/IDs/digests/tamanhos inválidos, assinatura errada, duplicatas, campos extras e trailing data.

`GOPROXY=off GOSUMDB=off GOMAXPROCS=4 make verify` passou: build, gofmt integral, vet normal/integration, sintaxe Bash, testes unitários, integrações PostgreSQL/SQLite/Floci três vezes e race detector. Houve uma falha inicial na integração por colisão entre marcador de subprocesso novo e helper unitário existente; os marcadores foram separados e a suíte completa passou depois da correção. Imagens/dependências já estavam preparadas; isso não prova instalação offline do produto.

## Limites obrigatórios

- Este é logical dump de um database; não inclui roles/globais, PITR/WAL, configuração completa, secrets, chaves internas, artefatos, OCI, outros formatos, pins, GC ou catálogo completo.
- Receipt cobre um archive e não assina object key/path, inventário de conteúdo, app/schema version, timestamp/freshness, retenção nem anti-replay. O operador fornece object keys em separado.
- Trust config local não tem processo de instalação/rotação/revogação; a chave Ed25519 privada é entregue ao produtor pelo controlador do teste. Não é recovery kit offline.
- Processo subprocesso ≠ isolamento de segurança: mesmo usuário/host, mesma implementação, e o verifier chama Docker CLI/contexto para entrar no container PostgreSQL fixture. Isso lhe dá acesso ao daemon configurado, não uma sandbox de produção. O S3 client exige endpoint literal loopback e credenciais explícitas, mas o host não tem política de egress testada.
- Mesmo com `--network=none` no PostgreSQL fixture, isso não prova isolamento do servidor do registry, verificador ou host. Floci não comprova atomicidade condicional concorrente contra S3/AWS/R2 real. Dois `PutObject` sequenciais não são commit transacional; receipt ausente pode deixar ciphertext órfão.
- Sem scheduler/job persistente, lease/pins, retry/reconciliação após timeout ou crash, limpeza após SIGKILL, retenção/prune, relatório autenticado, verificação de todos objetos, smoke tests dos sete formatos, modo manual offline operacional, instalação offline ou recovery em host novo.

Não converter esta evidência em aceite de backup completo, prontidão de produção, verificador operacional ou conclusão de fase 0. Backup lógico continua sem PITR/backup de cluster; limitações de sequence/MVCC permanecem conforme [spike PostgreSQL](postgres-backup.md).
