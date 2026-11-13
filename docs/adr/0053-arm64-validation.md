# ADR 0053 — Validação em Linux arm64

- **Status:** Validado por emulação QEMU de modo usuário; não em hardware arm64 real
- **Data:** 2026-11-12

## Contexto

O plano promete servidor Linux amd64 e arm64, mas nada havia sido executado em arm64. Não há máquina arm64 disponível; o host tem `qemu-aarch64` (modo usuário), sem registro `binfmt_misc` e sem root para registrá-lo.

## Decisão

O binário é compilado sem CGO para `linux/arm64` (`make build-arm64`) e as suítes rodam com `go test -exec qemu-aarch64` (`make verify-arm64`): os pacotes de teste arm64 executam emulados, enquanto PostgreSQL, Floci, os clientes reais (npm, Dart, ORAS, Chromium) e as fixtures continuam nativos amd64, falando com o servidor arm64 pela rede local.

## Resultado em 2026-11-12

- Passaram todos os pacotes de testes unitários e de integração, incluindo PostgreSQL e Floci reais, as jornadas do `serve` com npm, Dart, ORAS, storage S3, Muira, backup e restauração pelos comandos, migração de objetos e a interface web no Chromium com passkey.
- Não puderam rodar, por limite do ambiente: testes que reexecutam o próprio binário de teste como subprocesso (`TestSQLiteRebuildProcessCrashRollsBack`, dois testes do spike PostgreSQL) e testes que compilam um helper e o executam direto (`TestPublishGoClientAgainstLocalRegistry` e a jornada Cargo, que usa o `registryctl` como provider). Sem `binfmt_misc`, o kernel não executa binários arm64 fora do QEMU. Isso não indica defeito do produto, mas também não prova esses caminhos em arm64.
- **A replicação do SQLite não roda em arm64**: a biblioteca `sqlite-replication-go` só suporta captura em Linux amd64, e o `serve` recusa subir com replicação ligada em outra arquitetura. Em arm64, use os backups completos (ADR 0048).

## Limites

Emulação não reproduz desempenho, modelo de memória do hardware nem particularidades de kernel/filesystem arm64. Antes de anunciar arm64, rodar `make verify` numa máquina arm64 real (por exemplo uma VPS Ampere ou Graviton).
