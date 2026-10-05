# Spike 0.4 — PostgreSQL criptografado → S3/Floci → recuperação sem origem

**Data:** 04/10/2026

**Estado:** composição real do dump PostgreSQL com S3 emulado pelo Floci comprovada; não é backup completo da instalação nem verificador externo operacional.

## Objetivo e reprodução

Conectar os [spikes PostgreSQL](postgres-backup.md) e [S3/Floci](s3-backup.md), sem tratar o sucesso de cada componente isolado como prova da composição.

```sh
GOMAXPROCS=4 make setup-floci setup-postgres
GOMAXPROCS=4 go test -tags=integration -count=1 -run '^TestPostgresRemoteRecoveryWithoutOriginOrLocalArchive$' -v ./internal/spikes/postgresbackup
GOMAXPROCS=4 make verify
```

O teste está em `internal/spikes/postgresbackup/remote_integration_test.go`. Usa PostgreSQL 18.6 real e Floci 2.1.0, com as mesmas imagens fixadas por digest dos spikes anteriores. Não há MinIO, conta AWS, bucket compartilhado, credenciais cloud ou mock de cliente/storage.

PostgreSQL permanece no container exclusivo sem rede/portas. O teste inicia seu próprio Floci com nome aleatório e bucket exclusivo, credenciais locais `test/test`, assinatura S3 explicitamente exigida, apenas porta dinâmica de loopback e limites de 2 CPUs/512 MiB. Sem host mounts/Docker socket. Cleanup remove somente containers/volumes próprios. Floci ainda usa rede Docker padrão: isso não prova deny-by-default de egress do produto.

## Sequência comprovada

1. Criar dados sintéticos com chave estrangeira e 128 registros de conteúdo verificável.
2. `pg_dump` custom transmite plaintext diretamente ao age; somente ciphertext completo é escrito localmente, em arquivo exclusivo 0600.
3. Calcular SHA-256 do ciphertext em streaming e enviar o arquivo **já criptografado** por `PutObject` condicional. Não aplicar age pela segunda vez, não carregar archive completo na memória neste caminho de sucesso.
4. Fechar upload, excluir banco original com `dropdb`, remover ciphertext local e verificar que banco/arquivo não permanecem disponíveis.
5. Baixar por um novo `GetObject` S3, limitar bytes, validar digest independente do ciphertext e criar arquivo novo 0600, sem sobrescrever destino existente. Falha remove download parcial.
6. Criar banco vazio distinto. `Restore` autentica todo age e SHA-256 plaintext em staging privado limitado antes de `pg_restore --single-transaction --exit-on-error`.
7. Verificar exatamente 128 registros, payloads/referências esperados, foreign key restaurada e ausência de plaintext staging.

Evidência desta execução: **3.425 bytes de archive plaintext, 3.625 bytes de ciphertext**; origem e archive local ausentes antes de recuperar do objeto. No momento da prova não foi mantida cópia em bytes do archive original; mutações dos testes negativos são derivadas do objeto baixado posteriormente.

O caminho composto usa um objeto pequeno e um único `PutObject`, com ciphertext temporário local. **Não prova streaming direto pg_dump→multipart remoto**, nem o orçamento de spool para dumps grandes. Multipart, aborto e streaming age via pipe foram exercitados separadamente no spike S3; não são anunciados como integrados ao processo PostgreSQL aqui.

## Falhas da composição

Cada tentativa negativa usa outro banco vazio:

- adulteração/truncamento do objeto remoto: o teste atualiza inclusive o digest de ciphertext usado na tentativa, garantindo que a falha ocorra na autenticação age, não apenas no transporte;
- chave privada incorreta, objeto ausente, download cancelado, limite de ciphertext e digest divergente;
- destino de download preexistente: preservado sem sobrescrita;
- falha de download não mantém parcial; falha de restore não mantém plaintext staging; nenhuma tentativa negativa cria tabelas no banco alvo.

Os objetos de falha continuam sendo sintéticos; não representam autorização para alterar backups existentes. A comparação de metadados com ciphertext também rejeita exposição do texto sintético no objeto, sem pretender auditoria criptográfica do age.

`GOMAXPROCS=4 make verify` completo passou: build sem CGO, formatação, vet, sintaxe Bash, testes sem cache, SQLite/PostgreSQL/Floci três vezes e race detector com integração. Não foi executado benchmark de capacidade/RTO.

## Limitações preservadas

Os digests/recibos são evidências locais do experimento, **não um manifest autenticado autossuficiente**. A identidade age é efêmera em memória do teste; não é recovery kit exportado nem processo externo independente. Não existe servidor do produto, validação periódica, receipt assinado do verificador, reconstrução de identidades/configuração, blobs/OCI, pins/GC, quotas ou retries persistentes.

Cliente e emulador estão no mesmo host. Não comprova DR multi-host, backend AWS/R2 real, TLS operacional, atomicidade de conclusão concorrente, PITR ou compatibilidade de outras versões PostgreSQL. A corrida com dois vencedores no Floci 2.1.0 continua registrada e não foi mascarada. Próximos contratos obrigatórios da fase 0 incluem OCI, Hex, Authentik/SCIM, isolamento de rede e verificador externo completo.
