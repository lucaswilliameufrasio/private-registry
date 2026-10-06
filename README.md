# Private Registry

Registry privado self-hosted em desenvolvimento. **Ainda não existe servidor utilizável, release ou suporte anunciado a protocolos.** O repositório permanece privado, sem licença definida.

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

O plano e o roadmap também estão registrados no ai-memory, workspace `ursoc`, projeto `private-registry`, em `plans/development-plan.md` e `plans/roadmap.md`.

## Desenvolvimento

Requisitos desta entrega: Go 1.26 ou superior, Make, Bash e Docker para o Floci. Dependências fixadas em `go.mod`/`go.sum`; módulo local provisório `private-registry`. O remote confirmado é `git@github.com:lucaswilliameufrasio/private-registry.git`. O binário do spike não exige CGO.

```sh
go mod download
make verify
make spike-sqlite
```

`make verify` verifica build sem CGO, formatação de todo o repositório, `go vet`, sintaxe Bash, testes, integração SQLite/PostgreSQL/Floci repetida três vezes e race detector. O race detector exige toolchain C no ambiente de desenvolvimento; isso não é dependência do executável do spike.

Os testes usam bancos em arquivos temporários, não bancos mockados. O spike de linha de comando usa um diretório próprio em `/tmp/opencode`, remove apenas seus arquivos sintéticos e não recebe credenciais nem acessa produção. Em outras máquinas, criar previamente esse diretório com permissões apropriadas.

`make setup-floci` prepara a imagem Floci 2.1.0 fixada por digest; `test-integration` e `race` o executam como pré-requisito. Com a imagem presente, não há pull; os testes usam `--pull=never`. Para desenvolvimento offline, preparar dependências Go e carregar a imagem previamente com `docker load`.

Cada suíte inicia container Floci próprio, publica apenas em loopback/porta dinâmica e usa dados isolados e credenciais locais `test/test`. Verificação de assinatura S3 é ativada explicitamente. Não monta Docker socket nem dados do host; limita o container a 2 CPUs/512 MiB e remove apenas seu próprio container/volumes ao finalizar. Integração faltante falha, sem skip. Floci é emulador: não comprova compatibilidade integral nem garantias atômicas do storage de produção.

`make setup-postgres` prepara PostgreSQL 18.6 fixado por digest. A suíte inicia container próprio sem rede/portas/mounts, também limitado a 2 CPUs/512 MiB, e usa tools do mesmo major pelo socket Unix interno. Snapshot exportado preserva dados anteriores a commits concorrentes; dump é criptografado em streaming e restaurado depois de excluir o banco de origem. Sequences não são congeladas pelo snapshot MVCC. Ver detalhes/limites no terceiro spike.

Em máquina compartilhada, limitar o trabalho sem assumir que todos os recursos estão livres:

```sh
GOMAXPROCS=4 make verify
GOMAXPROCS=4 make spike-sqlite
```

## Estado atual

Fase 0 em andamento. Comprovado: Online Backup API do driver modernc com WAL, passos incrementais e escritas por outra conexão; age em streaming; restauração local e via S3/Floci com SHA-256, integridade SQLite e foreign keys, sem depender do snapshot/origem local. Multipart usa buffer fixo de ciphertext e cancela/aborta partes. Sobrescrita sequencial é rejeitada; **Floci 2.1.0 admitiu dois vencedores em uma corrida de conclusões condicionais**, portanto exclusão atômica não está comprovada. Corrupção, truncamento, chave errada, limite de plaintext e digest divergente não produzem restore válido.

PostgreSQL: snapshot exportado/dump age/restore em banco vazio comprovados com tools do mesmo major, com limites e rejeição de falhas. Ainda faltam demais contratos/spikes, incluindo OCI, Hex, Authentik/SCIM e mecanismos de produção para pins, quotas, jobs, material de recuperação e verificador externo. Nenhum desses experimentos é backup completo da instalação nem prova de compatibilidade com todo provider S3/R2. Não usar para dados importantes.

A composição PostgreSQL → age → objeto S3/Floci → banco novo também foi comprovada após exclusão da origem e do ciphertext local. Usa ciphertext temporário e `PutObject` de fixture pequena, não streaming direto pg_dump→multipart. Os testes rejeitam objetos danificados/chave errada e falhas de download sem criar tabelas no alvo; ver spike 0.4.

OCI inicial: `make setup-oci` prepara Distribution 3.1.2 e ORAS 1.3.4 fixados. Integração publica/consome artefato real via motor em socket Unix privado e gateway loopback; scopes e revogação de conta por requisição foram exercitados. Ainda não é gateway de produção nem aceite completo OCI (Docker/multiplataforma, quotas, review, backup/GC pendentes); ver spike 0.5.

OCI recuperação: índice amd64/arm64 e seis blobs alcançáveis reconstruídos de backup age após remover origem/exports; ORAS seleciona ambas as plataformas com digests preservados. GC read-only real remove órfão sem perder conteúdo alcançável. Ainda faltam Docker real, inventário global/referrers e coordenação durável online de publicação/backup/GC; ver spike 0.6.

Revisão OCI: ORAS falha se o manifest não for liberado; gate somente no manifest deixa blobs pendentes legíveis por digest. O probe 0.7 comprova mitigação por alcance publicado qualificado pelo repositório e revalidação de permissão antes de retry aprovado, sem workflow/projeção durável implementados.
