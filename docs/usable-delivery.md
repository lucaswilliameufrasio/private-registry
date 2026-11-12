# Entrega utilizável — Cargo, npm, Pub e OCI

**Atualizado:** 12/11/2026 · **Schema:** v44

Esta é a primeira entrega pensada para uso experimental de ponta a ponta. Ela **não é a v1** descrita em [development-plan.md](development-plan.md): o escopo foi reduzido por decisão do proprietário para quatro formatos, storage em objeto e login opcional via Muira. O que continua faltando para a v1 está em [O que esta entrega não cobre](#o-que-esta-entrega-não-cobre) e no [roadmap](roadmap.md).

Tudo aqui é opt-in e experimental. Há disaster recovery do banco SQLite por replicação, mas não um backup completo e independente; leia os limites antes de guardar dados que você não possa perder.

## O que está disponível

| Recurso | Como habilitar | Cliente real comprovado | Decisão |
| --- | --- | --- | --- |
| Cargo (sparse) | `REGISTRY_EXPERIMENTAL_CARGO=true` | Cargo 1.99.0: publish de dois crates (um com dependência privada) e build de um consumidor, usando o provider `registryctl` | [ADR 0031](adr/0031-cargo-publication-boundary.md) |
| npm | `REGISTRY_EXPERIMENTAL_NPM=true` | npm: publish e install de pacote scoped | [ADR 0039](adr/0039-npm-publication-boundary.md) |
| Pub (Dart) | `REGISTRY_EXPERIMENTAL_PUB=true` | Dart: publish e `pub get` | [ADR 0042](adr/0042-pub-catalog-boundary.md) |
| OCI | `REGISTRY_EXPERIMENTAL_OCI=true` | ORAS 1.3.4: push, pull, tags, retag. **Docker não comprovado** | [ADR 0044](adr/0044-own-oci-adapter.md) |
| Storage S3 compatível | `REGISTRY_STORAGE_DRIVER=s3` | npm pelo `serve` com bucket Floci. **R2/B2/S3 reais não comprovados** | [ADR 0019](adr/0019-s3-content-driver.md) |
| DR do banco | `REGISTRY_REPLICATION_ENABLED=true` | Ensaio de desastre pelos comandos reais, bucket Floci. **Provedor real não comprovado** | [ADR 0045](adr/0045-sqlite-replication-disaster-recovery.md) |
| Login Muira | `REGISTRY_MUIRA_ENABLED=true` | Provedor OIDC sintético. **Muira real não comprovado** | [ADR 0043](adr/0043-muira-identity-boundary.md) |

Arquivos genéricos e módulos Go continuam disponíveis como antes. Hex não faz parte desta entrega.

Todas as jornadas com cliente real passam pelo comando `serve` de verdade, atrás de um front TLS local, e preparam usuário, grants e tokens direto no banco/serviço: elas provam o protocolo, não a jornada administrativa pela API.

## Subindo uma instância

O servidor fica atrás de um proxy que termina TLS. Sem UI: a administração é pela API HTTP.

```sh
export REGISTRY_DATA_DIR=/var/lib/registry
export REGISTRY_MASTER_KEY_FILE=/etc/registry/master.key      # fora do data dir
export REGISTRY_CANONICAL_ORIGIN=https://registry.example.com
export REGISTRY_ASSET_ORIGIN=https://assets.registry.example.com
export REGISTRY_TRUSTED_PROXIES=127.0.0.1
export REGISTRY_EXPERIMENTAL_CARGO=true
export REGISTRY_EXPERIMENTAL_NPM=true
export REGISTRY_EXPERIMENTAL_PUB=true
export REGISTRY_EXPERIMENTAL_OCI=true

registry init-master-key
registry migrate            # sempre explícito; o serve nunca migra
registry bootstrap-admin    # interativo, cria o primeiro administrador
registry serve
```

Migrations continuam em Goose, aplicadas só por `registry migrate`. A v41 reconstrói `registry_repositories` no SQLite para aceitar o formato `oci`; pare o servidor antes de migrar.

### Storage em objeto (R2, B2, S3)

```sh
export REGISTRY_STORAGE_DRIVER=s3
export REGISTRY_S3_ENDPOINT=https://<account>.r2.cloudflarestorage.com
export REGISTRY_S3_REGION=auto
export REGISTRY_S3_BUCKET=registry-packages
export REGISTRY_S3_PREFIX=prod                                 # opcional
export REGISTRY_S3_ACCESS_KEY_ID_FILE=/etc/registry/s3-access-key-id
export REGISTRY_S3_SECRET_ACCESS_KEY_FILE=/etc/registry/s3-secret-access-key
export REGISTRY_S3_ALLOWED_NETWORKS=<CIDRs do endpoint>
export REGISTRY_S3_DNS_SERVER=1.1.1.1:53                       # obrigatório para endpoint por nome
```

- Os arquivos de credencial precisam ser do usuário do processo, modo `0600`/`0400`, sem symlink. Nada é lido de variáveis `AWS_*`.
- A saída só alcança o endpoint configurado, nos CIDRs configurados. Você precisa informar as redes do provedor; sem elas o servidor não sobe.
- Todos os formatos passam a guardar os bytes no bucket. **Continuam em disco local:** o banco SQLite, `<data>/s3-staging` (cada leitura e escrita baixa/gera o objeto inteiro ali para verificar o SHA-256) e os stagings de upload dos formatos. Reserve disco para isso: o teto do staging S3 é `(2 × 1 GiB + 1) × REGISTRY_S3_MAX_CONCURRENT` (default 8).
- Para migrar uma instância que já tem dados em filesystem: pare o `serve`, configure as variáveis acima e rode `registry migrate-objects` (verificado, repetível, não apaga a cópia local). Depois suba o `serve` e, quando estiver satisfeito, remova `<data>/object-store`. Ver [ADR 0047](adr/0047-offline-object-maintenance.md).
- Antes de confiar num provedor, valide nele: escrita condicional `If-None-Match: *` em `PutObject` (nenhum provedor foi verificado aqui; um que ignore a condição enfraquece a imutabilidade para quem tem escrita no bucket), objetos próximos de 1 GiB dentro do limite de 2 minutos por requisição, e comportamento sob falha.

### Login via Muira (opcional)

```sh
export REGISTRY_MUIRA_ENABLED=true
export REGISTRY_MUIRA_ISSUER=https://auth.lucaswilliameufrasio.com
export REGISTRY_MUIRA_CLIENT_ID=<client id>
export REGISTRY_MUIRA_CLIENT_SECRET_FILE=/etc/registry/muira-client-secret
export REGISTRY_MUIRA_ALLOWED_NETWORKS=<CIDRs do Muira>
export REGISTRY_MUIRA_DNS_SERVER=1.1.1.1:53
```

1. No console do Muira, registre um cliente com redirect URI exatamente `https://registry.example.com/api/v1/auth/muira/callback` e grave o segredo no arquivo acima.
2. O administrador local (criado no bootstrap) pode vincular a própria conta: `POST /api/v1/auth/muira/link` devolve a URL de autorização.
3. Para outras pessoas, o administrador pré-autoriza o `sub` do Muira (UUID do usuário, não o e-mail): `POST /api/v1/admin/muira/users` com `{"subject": "...", "display_name": "..."}`. A conta nasce sem senha local e **sem nenhum acesso**; membership e grants são atribuídos como para qualquer usuário.
4. Login: o navegador abre `GET /api/v1/auth/muira/start`.

O login local continua funcionando. O Muira substitui apenas a senha: quem administra a instância ou um workspace ainda precisa do TOTP local, e operações sensíveis continuam exigindo MFA local recente. Quem não foi vinculado nem pré-autorizado recebe 401 e nenhuma conta é criada.

Para contas locais, use convites (abaixo).

### Convidando pessoas

1. Uma vez, o administrador da instância permite cadastro por convite: `PUT /api/v1/admin/signup-policy` com `{"policy":"invitations"}`.
2. Um owner ou administrador do workspace cria o convite: `POST /api/v1/workspaces/{w}/invitations` com `{"role":"member"}`. O token aparece uma vez; entregue-o por um canal seu (não há email).
3. A pessoa cria a conta com `POST /api/v1/auth/invitations/redeem` (`token`, `login_name`, `display_name`, `password`) e faz login. Quem já tem conta, inclusive pelo Muira, usa `POST /api/v1/invitations/accept` com `{"token":"..."}` estando logado.
4. Conceda os grants de repositório; o convite dá só a membership.

Detalhes no [ADR 0046](adr/0046-workspace-invitations.md).

### Liberando espaço

A coleta OCI e as expirações só removem referências. Para apagar de fato os objetos que nada referencia, numa janela de manutenção com o `serve` parado: `registry collect-objects` (só relata) e depois `registry collect-objects --apply`. Objetos com menos de 24 h e qualquer objeto ainda referenciado são mantidos.

### Disaster recovery do banco (SQLite)

```sh
export REGISTRY_REPLICATION_ENABLED=true
export REGISTRY_REPLICATION_S3_ENDPOINT=https://<account>.r2.cloudflarestorage.com
export REGISTRY_REPLICATION_S3_REGION=auto
export REGISTRY_REPLICATION_S3_BUCKET=registry-dr
export REGISTRY_REPLICATION_S3_ACCESS_KEY_ID_FILE=/etc/registry/dr-access-key-id
export REGISTRY_REPLICATION_S3_SECRET_ACCESS_KEY_FILE=/etc/registry/dr-secret-access-key
export REGISTRY_REPLICATION_S3_ALLOWED_NETWORKS=<CIDRs do endpoint>
export REGISTRY_REPLICATION_S3_DNS_SERVER=1.1.1.1:53
```

O `serve` passa a enviar o banco para o bucket a cada 30 s quando há mudanças (`REGISTRY_REPLICATION_INTERVAL_SECONDS`), e mais uma vez ao encerrar. Use credenciais e, de preferência, bucket diferentes dos do object store. Só Linux amd64 e só SQLite. Detalhes e limites no [ADR 0045](adr/0045-sqlite-replication-disaster-recovery.md).

Para reconstruir um host perdido:

1. Restaure a chave mestra e os arquivos de credenciais a partir da **sua** cópia (o registry não os replica) e reconfigure as mesmas variáveis.
2. Com o diretório de dados vazio, rode `registry restore-database`. Ele nunca sobrescreve um banco existente.
3. Rode `registry serve`. Os pacotes voltam a ser servidos se o storage for S3; com storage em filesystem os bytes se perderam com o host.

Perde-se o que foi escrito depois do último envio, e o que foi revogado depois desse ponto precisa ser revogado de novo. Acompanhe `GET /api/v1/admin/replication` (campo `health` diferente de `current` pede atenção) ou os logs: cada ciclo que falha gera `WARN`, e a partir da terceira falha seguida, `ERROR`.

## Usando cada formato

Em todos os casos: crie o repositório com o formato certo (`POST /api/v1/workspaces/{workspace}/repositories` com `"format": "cargo" | "npm" | "pub" | "oci"`, só aceito com o adapter habilitado), conceda `reader`/`publisher` explicitamente (membership não dá acesso) e emita os tokens. Leitura usa o **token pessoal de leitura** (`…/personal-read-tokens`); publicação usa o **token de escrita do formato** (`…/cargo-write-tokens`, `…/npm-write-tokens`, `…/pub-write-tokens`, `…/oci-write-tokens`). Tokens são por repositório, expiram em até 30 dias e aparecem uma única vez.

### Cargo

O Cargo precisa de tokens diferentes para ler o índice e para publicar. O `registryctl` faz esse papel como credential provider:

```toml
# ~/.cargo/config.toml
[credential-alias]
private-registry = ["registryctl", "-index", "sparse+https://registry.example.com/cargo/<workspace>/<repository>/index/",
                    "-read-token-file", "/home/me/.config/registry/cargo-read",
                    "-write-token-file", "/home/me/.config/registry/cargo-write"]

[registries.private]
index = "sparse+https://registry.example.com/cargo/<workspace>/<repository>/index/"
credential-provider = "private-registry"
```

Os arquivos de token precisam ser `0600`. O provider só entrega token para o índice configurado e nunca permite cache pelo Cargo.

### npm

```ini
# .npmrc
@escopo:registry=https://registry.example.com/npm/<workspace>/<repository>/
//registry.example.com/npm/<workspace>/<repository>/:_authToken=<token>
```

Use o token de escrita para `npm publish` e o de leitura para `npm install`.

### Pub

```sh
dart pub token add https://registry.example.com/pub/<workspace>/<repository>
```

e `publish_to` / `hosted` apontando para a mesma URL.

### OCI

```sh
oras login registry.example.com -u token --password-stdin <<< "$OCI_WRITE_TOKEN"
oras push registry.example.com/<workspace>/<repository>/time/app:v1 ./arquivo
```

O usuário é ignorado; a senha é o token. Para pull, use o token pessoal de leitura.

Owners e administradores do workspace gerenciam o repositório pela API (CSRF e MFA recente): `PUT .../oci-policy` liga tags imutáveis, `DELETE .../oci-tags/{tag}?image=<nome>` remove uma tag e `DELETE .../oci-manifests/{digest}` remove um manifest e suas tags. A quota lógica do repositório e do workspace também vale para OCI. Blobs sem manifest são liberados depois de 24 h. Com `PUT .../oci-review-policy` ligado, manifests novos esperam aprovação de outro manager em `.../oci-reviews` antes de serem publicados. `docker login` aceita qualquer senha (o `/v2/` não tem como validar token por repositório); o erro aparece no primeiro push/pull.

## O que esta entrega não cobre

Itens obrigatórios da v1 que **não** estão feitos e afetam o uso:

- **Backup além do disaster recovery.** O banco SQLite tem replicação contínua e restore (seção acima), mas não há backup cifrado independente, retenção longa, verificador externo nem cobertura para PostgreSQL. As peças internas de inventário e recovery isolado continuam sem comando de operador e marcam o resultado como `RECOVERY_INCOMPLETE`; para OCI elas recusam a instalação.
- **OCI:** sem mount e referrers; objetos armazenados só são apagados pela coleta offline; Docker/containerd não comprovados; blob limitado a 1 GiB.
- **Storage S3:** sem qualificação em provedor real e sem multipart; migração e coleta de órfãos só offline.
- **Muira:** login real não validado; sem logout federado; callback responde JSON (não há UI).
- **Sem UI, email, passkeys, SCIM contínuo, contas de serviço, trusted publishing.**
- **Hex** e os demais requisitos do plano (egress global negado, verificador externo de backup, matriz de plataformas, benchmarks).
- Uma instância ativa; nada aqui foi testado com várias.

## Evidência desta entrega

- `cmd/registry`: jornadas pelo `serve` real com Cargo, npm, Dart e ORAS; npm com storage S3 (Floci); opt-in e recusa de Muira inalcançável.
- `internal/server`: jornadas HTTP de OCI e de Muira contra provedor sintético.
- `internal/oci`: mesma bateria em SQLite e PostgreSQL real.
- `internal/config`, `internal/secrets`, `internal/storage`, `cmd/registryctl`: configuração, arquivos de segredo, composição S3 e provider do Cargo.

Cada fatia passou três repetições com race nos testes focados.

Gate integral em 11/11/2026, sobre o commit `cbb8462`: build sem CGO, `format-check`, `go vet` (normal e integração), sintaxe dos scripts, unitários, integração com `-count=3` e integração com `-race -count=1` em todo o repositório, com `-timeout=40m` por pacote (o `Makefile` usa 20m) e cache Go dedicado. Na primeira execução o spike `internal/spikes/npmregistry` falhou por ambiente (o `PATH` tinha Node 26.13.0 e o spike exige 24.21.0), o que interrompeu a cadeia antes do estágio race; com Node 24.21.0 no `PATH`, esse pacote e `cmd/registry` passaram em três repetições e o estágio race passou inteiro. Não foi um único `make verify` contínuo. A jornada Docker ficou pulada (opt-in).
