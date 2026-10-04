# Private Registry

Registry privado self-hosted em desenvolvimento. **Ainda não existe servidor utilizável, release ou suporte anunciado a protocolos.** O repositório permanece privado, sem licença definida.

## Especificação

- [Plano completo da v1](docs/development-plan.md)
- [Roadmap e gaps conhecidos](docs/roadmap.md)
- [Primeiro spike: SQLite online + age + restore local](docs/spikes/sqlite-backup.md)

O plano e o roadmap também estão registrados no ai-memory, workspace `ursoc`, projeto `private-registry`, em `plans/development-plan.md` e `plans/roadmap.md`.

## Desenvolvimento

Requisitos desta primeira entrega: Go 1.26 ou superior e Make. Dependências fixadas em `go.mod`/`go.sum`; módulo local provisório `private-registry`, sem pressupor domínio ou URL pública do repositório. O binário do spike não exige CGO.

```sh
go mod download
make verify
make spike-sqlite
```

`make verify` verifica build sem CGO, formatação de todo o repositório, `go vet`, testes, integração SQLite real repetida três vezes e race detector. O race detector exige toolchain C no ambiente de desenvolvimento; isso não é dependência do executável do spike.

Os testes usam bancos em arquivos temporários, não bancos mockados. O spike de linha de comando usa um diretório próprio em `/tmp/opencode`, remove apenas seus arquivos sintéticos e não recebe credenciais nem acessa produção. Em outras máquinas, criar previamente esse diretório com permissões apropriadas.

Em máquina compartilhada, limitar o trabalho sem assumir que todos os recursos estão livres:

```sh
GOMAXPROCS=4 make verify
GOMAXPROCS=4 make spike-sqlite
```

## Estado atual

Fase 0 em andamento. Comprovado localmente: Online Backup API do driver modernc com WAL, passos incrementais e escritas por outra conexão; criptografia/decriptação age em streaming; restauração com SHA-256, integridade SQLite e foreign keys; rejeição de backup adulterado/truncado/chave incorreta e descarte de arquivos parciais.

Ainda faltam os demais contratos/spikes, incluindo PostgreSQL, S3/MinIO remoto, OCI, Hex, Authentik/SCIM e mecanismos de produção para pins, quotas, jobs, material de recuperação e verificador externo. Não usar este experimento para dados importantes.
