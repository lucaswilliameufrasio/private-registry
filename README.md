# Private Registry

Registry privado self-hosted em desenvolvimento. Há um esqueleto local `registry serve`, migrations da fundação de identidade/tenancy, serviço interno para workspaces, comandos locais para provisionar uma única conta administrativa inicial e inicializar uma chave mestra, e um envelope criptográfico ainda sem integração com persistência. **Ainda não há login/sessões, MFA, rotas administrativas ou de pacote, autorização/isolamento de conteúdo no servidor, servidor utilizável, release ou suporte anunciado a protocolos.** O repositório permanece privado, sem licença definida.

## Especificação

- [Plano completo da v1](docs/development-plan.md)
- [Roadmap e gaps conhecidos](docs/roadmap.md)
- [Primeiro spike: SQLite online + age + restore local](docs/spikes/sqlite-backup.md)
- [Segundo spike: backup criptografado e restore S3 via Floci](docs/spikes/s3-backup.md)
- [Terceiro spike: snapshot PostgreSQL + dump age + restore](docs/spikes/postgres-backup.md)
- [Quarto spike: PostgreSQL criptografado → S3/Floci → restore sem origem](docs/spikes/postgres-remote-backup.md)
- [Quinto spike: OCI Distribution/ORAS e revogação](docs/spikes/oci-auth.md)
- [Sexto spike: export OCI multiplataforma, restore e GC read-only](docs/spikes/oci-recovery-gc.md)
- [Sétimo spike: revisão OCI e proteção de blobs pendentes](docs/spikes/oci-review.md)
- [Oitavo spike: mount OCI entre repositórios e alcance publicado](docs/spikes/oci-mount.md)
- [Nono spike: janela de revogação durante commit OCI](docs/spikes/oci-commit-revocation.md)
- [Décimo spike: receipt OCI e alcance persistido/reconciliado](docs/spikes/oci-durable-release.md)
- [Spike 0.11: ordenação SQL de liberação e revogação](docs/spikes/oci-release-ordering.md)
- [Spike 0.12: ordenação SQL no PostgreSQL e lock de policy](docs/spikes/postgres-release-ordering.md)
- [Spike 0.13: verificador SQLite em processo separado sem origem](docs/spikes/external-backup-verifier.md)
- [Spike 0.14: autenticação do receipt de snapshot](docs/spikes/signed-backup-receipt.md)
- [Spike 0.15: verificador externo busca receipt e backup no Floci](docs/spikes/remote-signed-backup-verifier.md)
- [Spike 0.16: verificador externo de backup PostgreSQL remoto](docs/spikes/postgres-remote-external-verifier.md)
- [Spike 0.17: consumo Mix de registry Hex privado assinado](docs/spikes/hex-signed-registry.md)
- [Spike 0.18: Authentik OIDC/SCIM e lacuna de health/reconciliação](docs/spikes/authentik-oidc-scim.md)
- [Spike 0.19: cliente Go contra fixture de proxy de módulos](docs/spikes/go-module-proxy.md)
- [Spike 0.20: cliente Cargo contra registry sparse autenticado](docs/spikes/cargo-sparse-registry.md)
- [Spike 0.21: cliente npm contra registry scoped privado](docs/spikes/npm-registry.md)
- [Spike 0.22: cliente Pub contra Hosted Repository fixture](docs/spikes/pub-hosted-repository.md)
- [Modelo de ameaças inicial (rascunho)](docs/threat-model.md)
- [ADR 0001: driver SQLite](docs/adr/0001-sqlite-driver.md)
- [ADR 0002: URLs públicas e fronteiras de origem](docs/adr/0002-public-url-and-origin-boundaries.md)
- [ADR 0003: fronteiras de backup e validação de restore](docs/adr/0003-backup-and-restore-boundaries.md)
- [ADR 0004: identidade de autenticação e SCIM](docs/adr/0004-authentication-and-scim-identity.md)
- [ADR 0005: seleção do motor OCI bloqueada](docs/adr/0005-oci-engine-selection.md)
- [ADR 0006: fronteira de publicação Hex](docs/adr/0006-hex-publication-boundary.md)
- [ADR 0007: migrations versionadas dos bancos](docs/adr/0007-versioned-database-migrations.md)
- [ADR 0008: identidade e fundação de workspaces](docs/adr/0008-identity-and-workspace-foundation.md)
- [ADR 0009: bootstrap local e credenciais](docs/adr/0009-local-bootstrap-and-credentials.md)
- [ADR 0010: chave mestra local e envelopes criptográficos](docs/adr/0010-local-master-key-and-secret-envelopes.md)
- [ADR 0011: autenticação humana, MFA e sessões](docs/adr/0011-human-authentication-mfa-and-sessions.md)

O plano, o roadmap e o progresso de implementação também estão registrados no ai-memory, workspace `ursoc`, projeto `private-registry`, em `plans/development-plan.md`, `plans/roadmap.md` e `plans/implementation-progress.md`.

## Desenvolvimento

Requisitos desta entrega: Go 1.26 ou superior, Make, Bash, Docker Compose para fixtures de integração (Floci, PostgreSQL, OCI, Authentik e Valkey), Mix/Hex fixados, Rustup/Cargo 1.99.0, Node.js/npm 24.21.0/11.19.0 e Dart SDK 3.13.5 para os contratos de cliente. Se `dart` não estiver no `PATH`, indique `PUB_TEST_DART_BIN=/path/to/dart`. Dependências Go fixadas em `go.mod`/`go.sum`; módulo local provisório `private-registry`. O remote confirmado é `git@github.com:lucaswilliameufrasio/private-registry.git`. O binário do spike não exige CGO.

```sh
go mod download
make verify
make spike-sqlite
```

O binário atual oferece somente fundação local: `go run ./cmd/registry migrate` aplica explicitamente o schema v1–v3; `go run ./cmd/registry bootstrap-admin` cria uma única conta local com username, email de contato e senha Argon2id, apenas em terminal interativo; `go run ./cmd/registry init-master-key` gera uma chave local Linux; `go run ./cmd/registry serve` expõe apenas health checks. Bootstrap não migra schema, não recebe senha por argumento/ambiente e não cria rota HTTP. O comando de chave não imprime nem sobrescreve a chave e não requer banco/migrations. Login/sessões, MFA, rotas administrativas, autenticação e autorização de conteúdo ainda não existem. A configuração é via `REGISTRY_LISTEN_ADDRESS`, `REGISTRY_DATA_DIR`, `REGISTRY_MASTER_KEY_FILE` (caminho do arquivo, não o valor da chave), `REGISTRY_DATABASE_DRIVER`, `REGISTRY_DATABASE_DSN` e `REGISTRY_DATABASE_MAX_OPEN_CONNS`. Não execute migrations com a instância ativa; backup-gate e procedimento de upgrade de produção ainda não existem.

Para inicializar a chave, configure `REGISTRY_DATA_DIR` e `REGISTRY_MASTER_KEY_FILE`; o diretório pai da chave deve existir e estar protegido. O caminho da chave deve ficar fora do diretório de dados. Em Linux, `init-master-key` cria 32 bytes aleatórios com permissão `0600`, recusa caminhos inseguros e falha se o arquivo já existir. Guarde uma cópia de recuperação separada do banco/diretório de dados: perder a chave torna irrecuperáveis os segredos que vierem a ser cifrados. Neste estágio, o envelope XChaCha20-Poly1305 é apenas uma primitiva testada; nenhum segredo é persistido por ela, e ainda não há backup/kit de recuperação, rotação de chave ou MFA.

`make verify` verifica build sem CGO, formatação de todo o repositório, `go vet`, sintaxe Bash, testes, integração SQLite/PostgreSQL/Floci/OCI/Authentik/Hex/Go/Cargo/npm/Pub repetida três vezes, além do race detector. Os pacotes de integração rodam serializados para não competir pelos limites das fixtures em containers. Os contratos de clientes usam fixtures locais efêmeras, sem registry de produção. Pub testa Dart SDK 3.13.5 em localhost; HTTP ali é exceção exclusiva da fixture e não prova TLS de produção. A verificação integral mais recente, incluindo migration v3, bootstrap e a fundação da chave mestra, passou em 18/10/2026: `GOMAXPROCS=4 GOPROXY=off GOSUMDB=off PUB_TEST_DART_BIN=/home/lucaseufrasio/fvm/versions/3.47.7/bin/cache/dart-sdk/bin/dart make verify`, incluindo integração 3× e race 1×. `go build ./...` também passou para Windows amd64 e macOS arm64. Uma falha transitória anterior na fixture Authentik foi reproduzida uma vez e não teve causa-raiz demonstrada; a execução integral atual passou. Isso não prova operação offline do produto. O race detector exige toolchain C no ambiente de desenvolvimento; isso não é dependência do executável do spike.

Os testes usam bancos em arquivos temporários, não bancos mockados. A integração de migrations testa SQLite e PostgreSQL reais; PostgreSQL fica em container `--network=none`, com socket Unix temporário compartilhado e sem porta publicada. O spike de linha de comando usa um diretório próprio em `/tmp/opencode`, remove apenas seus arquivos sintéticos e não recebe credenciais nem acessa produção. Em outras máquinas, criar previamente esse diretório com permissões apropriadas.

`make setup-floci` prepara a imagem Floci 2.1.0 fixada por digest; `test-integration` e `race` o executam como pré-requisito. Com a imagem presente, não há pull; os testes usam `--pull=never`. Para desenvolvimento offline, preparar dependências Go e carregar a imagem previamente com `docker load`.

`make setup-authentik` prepara Authentik 2026.8.3, PostgreSQL 18.6 e Valkey 9.0.3 fixados por digest. A fixture é isolada, sem portas publicadas nem saída de rede, e aplica limites de recursos; o teste verifica OIDC e SCIM reais contra um target SCIM sintético.

Cada suíte inicia container Floci próprio, publica apenas em loopback/porta dinâmica e usa dados isolados e credenciais locais `test/test`. Verificação de assinatura S3 é ativada explicitamente. Não monta Docker socket nem dados do host; limita o container a 2 CPUs/512 MiB e remove apenas seu próprio container/volumes ao finalizar. Integração faltante falha, sem skip. Floci é emulador: não comprova compatibilidade integral nem garantias atômicas do storage de produção.

`make setup-postgres` prepara PostgreSQL 18.6 fixado por digest. A suíte inicia container próprio sem rede/portas/mounts, também limitado a 2 CPUs/512 MiB, e usa tools do mesmo major pelo socket Unix interno. Snapshot exportado preserva dados anteriores a commits concorrentes; dump é criptografado em streaming e restaurado depois de excluir o banco de origem. Sequences não são congeladas pelo snapshot MVCC. Ver detalhes/limites no terceiro spike.

Em máquina compartilhada, limitar o trabalho sem assumir que todos os recursos estão livres:

```sh
GOMAXPROCS=4 make verify
GOMAXPROCS=4 make spike-sqlite
```

## Estado atual

Fase 0 em andamento; a fase 1 ainda não está completa. A fundação executável segue parcial: configuração, DB, health/drain, migrations v1–v3, bootstrap local one-shot, criação local da chave mestra e serviço interno de criação de workspace existem; login/sessões/MFA, APIs e isolamento de conteúdo ainda não. O envelope criptográfico não está ligado a persistência. Os testes SQLite/PostgreSQL exercitam criação de workspace segundo policy independente de cadastro, owner inicial, grants revogáveis, auditoria, subject federado único e slug imutável. Isso não valida autorização de downloads/pacotes. Comprovado: Online Backup API do driver modernc com WAL, passos incrementais e escritas por outra conexão; age em streaming; restauração local e via S3/Floci com SHA-256, integridade SQLite e foreign keys, sem depender do snapshot/origem local. Multipart usa buffer fixo de ciphertext e cancela/aborta partes. Sobrescrita sequencial é rejeitada; **Floci 2.1.0 admitiu dois vencedores em uma corrida de conclusões condicionais**, portanto exclusão atômica não está comprovada. Corrupção, truncamento, chave errada, limite de plaintext e digest divergente não produzem restore válido.

PostgreSQL: snapshot exportado/dump age/restore em banco vazio comprovados com tools do mesmo major, com limites e rejeição de falhas. Spikes OCI, Hex, Go, Cargo, npm e Pub têm evidência limitada, não servidores utilizáveis. Os spikes 0.19–0.22 exercitam clientes reais contra fixtures; Pub prova publicação/consumo sintéticos no Dart 3.13.5, mas usa HTTP localhost e não valida TLS, Flutter CLI nem matriz Windows/macOS. Nenhum implementa adapter nem anuncia suporte de produto. O spike 0.18 caracteriza OIDC/SCIM: sob 503 não houve sinal health útil e o resultado da sincronização variou; em observações repetidas, a full sync leu Users, às vezes sem `PUT/PATCH` e deixando drift, e numa execução houve uma atualização que coincidiu com a correção do drift. Isso não comprova reconciliação determinística. A fixture permissiva também reteve recursos sintéticos duplicados de Groups (4–6 observados); unicidade SCIM real não foi comprovada. Health/freshness, reconciliação autoritativa, bloqueio após uma hora e desbloqueio auditado permanecem obrigatórios. Também faltam mecanismos de produção para pins, quotas, jobs, material de recuperação e verificador externo. Nenhum experimento é backup completo da instalação nem prova compatibilidade com todo provider S3/R2. Não usar para dados importantes.

A composição PostgreSQL → age → objeto S3/Floci → banco novo também foi comprovada após exclusão da origem e do ciphertext local. Usa ciphertext temporário e `PutObject` de fixture pequena, não streaming direto pg_dump→multipart. Os testes rejeitam objetos danificados/chave errada e falhas de download sem criar tabelas no alvo; ver spike 0.4.

OCI inicial: `make setup-oci` prepara Distribution 3.1.2 e ORAS 1.3.4 fixados. Integração publica/consome artefato real via motor em socket Unix privado e gateway loopback; scopes e revogação de conta por requisição foram exercitados. Ainda não é gateway de produção nem aceite completo OCI (Docker/multiplataforma, quotas, review, backup/GC pendentes); ver spike 0.5.

OCI recuperação: índice amd64/arm64 e seis blobs alcançáveis reconstruídos de backup age após remover origem/exports; ORAS seleciona ambas as plataformas com digests preservados. GC read-only real remove órfão sem perder conteúdo alcançável. Ainda faltam Docker real, inventário global/referrers e coordenação durável online de publicação/backup/GC; ver spike 0.6.

Revisão OCI: ORAS falha se o manifest não for liberado; gate somente no manifest deixa blobs pendentes legíveis por digest. O probe 0.7 comprova mitigação por alcance publicado qualificado pelo repositório e revalidação de permissão antes de retry aprovado, sem workflow/projeção durável implementados.
