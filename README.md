# Private Registry

Registry privado self-hosted em desenvolvimento. A fundação contém migrations explícitas de identidade/tenancy/MFA/sessões, autenticação local e rotas HTTP protegidas para workspaces, memberships, metadados/configuração de repositórios e gestão de grants explícitos. **Ainda não há UI, passkeys, convites ou adapters produtivos. O serving genérico privado e público é parcial; não há suporte anunciado aos sete formatos.** Fase 1 permanece incompleta e não há servidor utilizável, release ou suporte anunciado a protocolos. O repositório permanece privado, sem licença definida.

**Atualização de schema:** a migration atual é a v24. Ela inclui fundações experimentais de catálogo, credencial, reservas, recibos, revisão e publicação Cargo; o adapter continua opt-in e a API recusa a criação de repositórios Cargo. O comando `serve` verifica o histórico e os checksums das migrations antes de abrir o listener, mas não executa migrations. Referências históricas abaixo a versões anteriores precedem essa atualização.

**Trabalhos recuperados:** após uma futura promoção segura, `GET /api/v1/admin/jobs/recovery` lista metadados limitados de jobs suspensos para administradores. `POST /api/v1/admin/jobs/{jobID}/release-recovery` libera somente jobs idempotentes de expiração de uploads genéricos ou Go, com MFA recente, CSRF, `expected_revision` e `confirm_destinations_and_policies: true`; a confirmação é declaração do operador, não validação automática. Outros jobs e uploads invalidados seguem bloqueados. A preparação experimental de SQLite continua deixando `RECOVERY_INCOMPLETE`, e não há promoção operacional completa.

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
- [ADR 0012: baseline de segurança do toolchain Go](docs/adr/0012-go-toolchain-security-baseline.md)
- [ADR 0013: repositórios e visibilidade](docs/adr/0013-repositories-and-visibility.md)
- [ADR 0014: grants aditivos de repositório](docs/adr/0014-repository-grants.md)
- [ADR 0015: storage filesystem imutável](docs/adr/0015-content-addressed-filesystem-storage.md)
- [ADR 0016: publicação de artefatos genéricos](docs/adr/0016-generic-artifact-publication.md)
- [ADR 0022: fronteira experimental de módulos Go](docs/adr/0022-go-module-boundary.md)

O plano, o roadmap e o progresso de implementação também estão registrados no ai-memory, workspace `ursoc`, projeto `private-registry`, em `plans/development-plan.md`, `plans/roadmap.md` e `plans/implementation-progress.md`.

## Desenvolvimento

Requisitos desta entrega: Go 1.26.10 ou superior; o `go.mod` prefere Go 1.27.3 para incluir correções de segurança da biblioteca padrão. Também são necessários Make, Bash, Docker Compose para fixtures de integração (Floci, PostgreSQL, OCI, Authentik e Valkey), Mix/Hex fixados, Rustup/Cargo 1.99.0, Node.js/npm 24.21.0/11.19.0 e Dart SDK 3.13.5 para os contratos de cliente. Se `dart` não estiver no `PATH`, indique `PUB_TEST_DART_BIN=/path/to/dart`. Dependências Go fixadas em `go.mod`/`go.sum`; módulo local provisório `private-registry`. O remote confirmado é `git@github.com:lucaswilliameufrasio/private-registry.git`. O binário do spike não exige CGO.

```sh
go mod download
make verify
make spike-sqlite
```

O binário oferece esta fundação local: `go run ./cmd/registry migrate` aplica explicitamente o schema v1–v15; `go run ./cmd/registry bootstrap-admin` cria uma única conta local com username, email de contato e senha Argon2id, apenas em terminal interativo; `go run ./cmd/registry init-master-key` gera uma chave local Linux; `go run ./cmd/registry serve` expõe health checks, autenticação e rotas administrativas autenticadas para workspaces, memberships, metadados/configuração de repositórios e grants. Owners podem conceder qualquer papel fixo; administradores delegam apenas `reader`/`publisher`; remover membership revoga grants, e readmissão não os restaura. Escritas exigem `Origin` e CSRF, e mutações sensíveis exigem MFA recente. Novos repositórios são privados. A publicação de artefatos genéricos exige grants `publisher` e MFA recente; manifesto exige `reader`; o link temporário serve somente na origem distinta `REGISTRY_ASSET_ORIGIN`. `unlisted`/`listed` permitem serving anônimo genérico somente na origem de assets; cache e CORS continuam restritos. Bootstrap não migra schema, não recebe senha por argumento/ambiente e não cria rota HTTP. O comando de chave não imprime nem sobrescreve a chave e não requer banco/migrations. A configuração usa `REGISTRY_LISTEN_ADDRESS`, `REGISTRY_DATA_DIR`, `REGISTRY_MASTER_KEY_FILE` (caminho do arquivo, não o valor da chave), `REGISTRY_CANONICAL_ORIGIN` (origem HTTPS exigida por `serve`), `REGISTRY_ASSET_ORIGIN` (origem HTTPS distinta, também exigida por `serve`), `REGISTRY_TRUSTED_PROXIES` (IP/CIDR do proxy TLS, obrigatório por `serve`), `REGISTRY_DATABASE_DRIVER`, `REGISTRY_DATABASE_DSN` e `REGISTRY_DATABASE_MAX_OPEN_CONNS`, `REGISTRY_MAX_UPLOAD_BYTES` (default 1 GiB, teto 1 GiB) e `REGISTRY_MAX_CONCURRENT_UPLOADS` (default 4 por processo). Não execute migrations com a instância ativa; backup-gate e procedimento de upgrade de produção ainda não existem.

**CLI Go experimental:** `registryctl pack go -dir DIRETORIO -version VERSAO -out ARQUIVO` empacota localmente sem sobrescrever a saída. `registryctl publish go -url ORIGEM_HTTPS -workspace UUID -repository UUID -dir DIRETORIO -version VERSAO -source-time RFC3339 -login USUARIO` solicita senha e MFA no terminal, envia o pacote e informa o ID da sessão. Um recibo aguardando revisão não é publicação. Use `registryctl publication status` ou `registryctl publication finalize`, com `-url`, `-workspace`, `-repository`, `-id` e `-login`, para consultar ou finalizar após aprovação. Essas operações são experimentais: o prompt foi exercitado em pseudoterminal Linux, mas a execução em outras plataformas ainda não foi verificada; não há login federado nem uso não interativo, e o backup completo permanece pendente. Em configurações Go mistas, use fallback com vírgula, nunca `|`; não desligue globalmente o checksum público.

Para inicializar a chave, configure `REGISTRY_DATA_DIR` e `REGISTRY_MASTER_KEY_FILE`; o diretório pai da chave deve existir e estar protegido. O caminho da chave deve ficar fora do diretório de dados. Em Linux, `init-master-key` cria 32 bytes aleatórios com permissão `0600`, recusa caminhos inseguros e falha se o arquivo já existir. `serve` requer a chave, `REGISTRY_CANONICAL_ORIGIN=https://registry.example`, `REGISTRY_ASSET_ORIGIN=https://assets.example` (host HTTPS distinto) e `REGISTRY_TRUSTED_PROXIES` com o IP/CIDR do proxy TLS; esse proxy deve preservar o `Host` canônico e definir `X-Forwarded-Proto: https`. Sem TLS direto ou essa asserção vinda do peer confiável, as rotas de autenticação rejeitam a requisição. `X-Forwarded-For` só é usado quando a conexão vem de um IP/CIDR confiável; headers de host nunca são derivados de forwarding. O enrollment TOTP persiste o seed com envelope XChaCha20-Poly1305 e AAD vinculada ao usuário. Guarde cópia de recuperação da chave separada do banco/diretório de dados: perdê-la torna irrecuperáveis os seeds. Backup/kit de recuperação e rotação ainda não existem.

`make verify` verifica build sem CGO, formatação de todo o repositório, `go vet`, sintaxe Bash, testes, integração SQLite/PostgreSQL/Floci/OCI/Authentik/Hex/Go/Cargo/npm/Pub repetida três vezes, além do race detector. Os pacotes de integração rodam serializados para não competir pelos limites das fixtures em containers. Os contratos de clientes usam fixtures locais efêmeras, sem registry de produção. Pub testa Dart SDK 3.13.5 em localhost; HTTP ali é exceção exclusiva da fixture e não prova TLS de produção. O gate integral da revisão anterior às migrations v9/v10 foi executado com `TMPDIR=/home/lucaseufrasio/.cache/private-registry-race-tmp.ggcqJ3`, `GOMAXPROCS=4` e `PUB_TEST_DART_BIN=/home/lucaseufrasio/fvm/versions/3.47.7/bin/cache/dart-sdk/bin/dart` e passou: build sem CGO, format-check, vet normal/integration, sintaxe Bash, unitários, integrações três vezes (incluindo Authentik) e race uma vez. A fixture Authentik agora cria seu `.env` privado no diretório indicado por `TMPDIR` (fallback `/tmp/opencode`), em vez de depender de espaço em `/tmp/opencode`; os quatro containers stale autorizados foram removidos antes da execução. O relatório observado do Authentik continua sem aceitar health/freshness ou reconciliação determinística. Builds sem CGO passaram para Linux amd64/arm64, Windows amd64 e macOS amd64/arm64. `govulncheck ./...` com Go 1.27.3 encontrou zero vulnerabilidades alcançáveis; permanece o advisory de módulo GO-2026-5932 em `golang.org/x/crypto/openpgp`, pacote não chamado pelo projeto. A atualização para Go 1.27.3/1.26.10 também removeu o finding alcançável GO-2026-6809 da stdlib `crypto/x509`. Isso não prova operação offline do produto. O race detector exige toolchain C no ambiente de desenvolvimento; isso não é dependência do executável do spike.

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

### Artefatos genéricos — fundação parcial

Validação desta fatia em 25/10/2026: `make verify` integral passou (build, format-check, vet, unitários, integrações 3× e race 1×). Ambiente local: `GOMAXPROCS=4`, `TMPDIR=/home/lucaseufrasio/.cache/private-registry-race-tmp.ggcqJ3`, `PUB_TEST_DART_BIN=/home/lucaseufrasio/fvm/versions/3.47.7/bin/cache/dart-sdk/bin/dart`, `MIX_HOME=/home/lucaseufrasio/.cache/private-registry-hex-2.5.1-otp28-home` e `MIX_ARCHIVES=/home/lucaseufrasio/.cache/private-registry-hex-2.5.1-otp28-archives`. Hex 2.5.1 foi compilado isoladamente com Elixir 1.19.5/OTP 28.4; não houve alteração dos defaults globais. A aprovação do gate não encerra a v1.

O fluxo administrativo exige sessão autenticada, MFA recente para uploads/publicação/emissão de links, grant `publisher` para publicar e grant `reader` para consultar manifestos ou solicitar download. As rotas são `POST /api/v1/workspaces/{workspaceID}/repositories/{repositoryID}/artifacts/uploads` (metadados de arquivo), `PUT .../artifacts/uploads/{uploadSessionID}` (`application/octet-stream`), `POST .../artifacts/{artifactVersionID}/publish` e `GET .../artifacts/{artifactVersionID}`. A sessão é reivindicada atomicamente antes de ler o body, então PUT concorrente para o mesmo session ID é rejeitado sem consumir conteúdo; falha transitória restaura a sessão para retry. Claims abandonadas expiram após 24h e são reconciliadas lazy e por worker periódico persistido.

O download-link é emitido por `POST .../artifacts/{artifactVersionID}/files/{fileID}/download-link`. O link aleatório é capability bearer de 5 minutos por default (máximo de 15), guardado no banco apenas como SHA-256, e só funciona em `REGISTRY_ASSET_ORIGIN`, HTTPS distinto da origem canônica. Nessa origem, `GET`/`HEAD /api/v1/assets/{ticket}` envia como attachment, `nosniff`, `private, no-store`, ETag e byte range único. O conteúdo executável nunca é servido inline pela origem administrativa. Grant revogado impede novos links, mas um ticket já entregue segue utilizável até expirar.

Repositórios explicitamente públicos (`unlisted` ou `listed`) oferecem `GET`/`HEAD /public/{workspace-slug}/{repository-slug}/{collection}/{version}/{path...}` na origem de assets. O padrão ainda é privado. Respostas públicas usam `no-store` e HTML é sujeito a CSP sandbox. CORS é desligado por padrão; `REGISTRY_PUBLIC_ASSET_CORS_ORIGINS` aceita uma lista de origens HTTPS explícitas separadas por vírgula, aplicada apenas a assets públicos e sem credenciais. CDN, cache público e documentação interativa ainda não estão aceitos. Detalhes: [ADR 0020](docs/adr/0020-public-generic-assets.md).

Tokens pessoais de leitura iniciais permitem manifesto e download genérico via `Authorization: Bearer`, restritos a um repositório e ao grant `reader` específico vigente na emissão. A criação exige MFA recente; o segredo aparece uma única vez, e revogação ou perda do grant impede novas autenticações. Requisições já autenticadas podem concluir após revogação. Não há publicação por token nem suporte a clientes nativos nesta fatia; consulte [ADR 0021](docs/adr/0021-personal-read-tokens.md).

`REGISTRY_MAX_UPLOAD_BYTES` limita cada arquivo (default/teto 1 GiB) e `REGISTRY_MAX_CONCURRENT_UPLOADS` limita uploads simultâneos **por processo** (default 4). Quotas lógicas opcionais para genéricos são reservadas atomicamente e administradas com revisão e auditoria; não cobrem outros formatos nem quota global. O backend ativo é filesystem imutável em `REGISTRY_DATA_DIR/object-store`; o driver S3 isolado ainda não é selecionável. Limpeza de staging, reconciliação/GC de objetos órfãos, métricas de tráfego, UI/CLI e adapters Pub/Go/Cargo/npm/Hex/OCI continuam pendentes. A v1 continua aberta.

## Estado atual

Fase 0 em andamento; a fase 1 ainda não está completa. A fundação executável segue parcial: configuração, DB, health/drain, migrations v1–v15, bootstrap local one-shot, criação local da chave mestra, serviços internos de workspaces/repositórios, login local, enrollment/confirmação TOTP, limites de tentativas, sessões e rotas HTTP autenticadas de workspace, membership, metadados/configuração de repositórios e grants existem. As escritas aplicam CSRF, Origin/Host canônicos e trusted proxies configurados; mutações sensíveis exigem MFA recente. Membership não concede leitura/publicação: grants são explícitos e aditivos; administradores delegam apenas `reader`/`publisher`; a remoção da membership revoga grants sem restauração automática na readmissão. A política começa em `private_only`, novos repositórios são privados e mudar a política não converte os existentes. **A fatia de artefatos genéricos agora inclui catálogo, upload/publicação explícitos e download privado por ticket na origem de assets separada; serving público genérico inicial usa origem de assets, sem cache compartilhado e com CORS opcional restrito; adapters de protocolo continuam ausentes.** Passkeys, OIDC/SCIM, convites, APIs de pacote, backup/kit/rotação da chave e restante do aceite da fase seguem pendentes. Login aplica 5 tentativas por conta e 20 por IP em janela móvel de 15 minutos, sem bloqueio permanente, limita Argon2 a duas operações simultâneas e rejeita excesso sem fila. Os testes SQLite/PostgreSQL exercitam autorização de metadados/grants e, na fatia genérica, publicação, revogação e download autorizado por ticket/range; isso não valida adapters de pacotes nem os outros formatos. Comprovado: Online Backup API do driver modernc com WAL, passos incrementais e escritas por outra conexão; age em streaming; restauração local e via S3/Floci com SHA-256, integridade SQLite e foreign keys, sem depender do snapshot/origem local. Multipart usa buffer fixo de ciphertext e cancela/aborta partes. Sobrescrita sequencial é rejeitada; **Floci 2.1.0 admitiu dois vencedores em uma corrida de conclusões condicionais**, portanto exclusão atômica não está comprovada. Corrupção, truncamento, chave errada, limite de plaintext e digest divergente não produzem restore válido.

PostgreSQL: snapshot exportado/dump age/restore em banco vazio comprovados com tools do mesmo major, com limites e rejeição de falhas. Spikes OCI, Hex, Go, Cargo, npm e Pub têm evidência limitada, não servidores utilizáveis. Os spikes 0.19–0.22 exercitam clientes reais contra fixtures; Pub prova publicação/consumo sintéticos no Dart 3.13.5, mas usa HTTP localhost e não valida TLS, Flutter CLI nem matriz Windows/macOS. Nenhum implementa adapter nem anuncia suporte de produto. O spike 0.18 caracteriza OIDC/SCIM: sob 503 não houve sinal health útil e o resultado da sincronização variou; em observações repetidas, a full sync leu Users, às vezes sem `PUT/PATCH` e deixando drift, e numa execução houve uma atualização que coincidiu com a correção do drift. Isso não comprova reconciliação determinística. A fixture permissiva também reteve recursos sintéticos duplicados de Groups (4–6 observados); unicidade SCIM real não foi comprovada. Health/freshness, reconciliação autoritativa, bloqueio após uma hora e desbloqueio auditado permanecem obrigatórios. Também faltam mecanismos de produção para pins, quotas, jobs, material de recuperação e verificador externo. Nenhum experimento é backup completo da instalação nem prova compatibilidade com todo provider S3/R2. Não usar para dados importantes.

A composição PostgreSQL → age → objeto S3/Floci → banco novo também foi comprovada após exclusão da origem e do ciphertext local. Usa ciphertext temporário e `PutObject` de fixture pequena, não streaming direto pg_dump→multipart. Os testes rejeitam objetos danificados/chave errada e falhas de download sem criar tabelas no alvo; ver spike 0.4.

OCI inicial: `make setup-oci` prepara Distribution 3.1.2 e ORAS 1.3.4 fixados. Integração publica/consome artefato real via motor em socket Unix privado e gateway loopback; scopes e revogação de conta por requisição foram exercitados. Ainda não é gateway de produção nem aceite completo OCI (Docker/multiplataforma, quotas, review, backup/GC pendentes); ver spike 0.5.

OCI recuperação: índice amd64/arm64 e seis blobs alcançáveis reconstruídos de backup age após remover origem/exports; ORAS seleciona ambas as plataformas com digests preservados. GC read-only real remove órfão sem perder conteúdo alcançável. Ainda faltam Docker real, inventário global/referrers e coordenação durável online de publicação/backup/GC; ver spike 0.6.

Revisão OCI: ORAS falha se o manifest não for liberado; gate somente no manifest deixa blobs pendentes legíveis por digest. O probe 0.7 comprova mitigação por alcance publicado qualificado pelo repositório e revalidação de permissão antes de retry aprovado, sem workflow/projeção durável implementados.
