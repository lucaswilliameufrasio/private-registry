# Spike 0.20 — cliente Cargo contra registry sparse autenticado

**Data:** 13/10/2026

**Estado:** Cargo 1.99.0 real publicou, consumiu e yankou crates sintéticos contra API/index sparse HTTP local com autenticação. Não é adapter do registry, deployment seguro nem suporte Cargo de produção.

## Reprodução e isolamento

```sh
GOMAXPROCS=4 GOPROXY=off GOSUMDB=off go test -tags=integration -count=3 -v ./internal/spikes/cargoregistry
GOMAXPROCS=4 GOPROXY=off GOSUMDB=off go test -race -tags=integration -count=1 ./internal/spikes/cargoregistry
```

O teste exige Rustup com toolchain `1.99.0-x86_64-unknown-linux-gnu`, Cargo 1.99.0 e rustc 1.99.0. O subprocesso executa diretamente o binário do toolchain; não depende de seleção de versão do diretório temporário. Cada caso usa `CARGO_HOME`, `CARGO_TARGET_DIR`, workspace e crates temporários próprios. O credential provider integrado `cargo:token` recebe token aleatório sintético pela variável do registry; nenhum valor de credencial é impresso ou salvo no checkout. Proxy HTTP(S) para loopback porta 9 impede fallback externo; `NO_PROXY` libera apenas o endpoint fixture loopback. O servidor não publica portas externas nem acessa serviços reais.

## Contrato exercitado

1. `config.json` anuncia sparse index, API, template de download e `auth-required: true`. Só a leitura desse bootstrap é pública; index, download e API exigem o token sintético.
2. `cargo publish --registry private` envia dois pacotes pelo `PUT /api/v1/crates/new`. A fixture lê o framing binário versionado pelo protocolo, verifica comprimento, checksum e identidade do `Cargo.toml` no `.crate`, e materializa entradas no índice sparse.
3. O crate consumidor tem dependência privada transitiva, seleciona feature no crate pai e exercício de feature default no leaf; `cargo run` compila e obtém o resultado esperado exclusivamente do registry privado.
4. `cargo yank` usa `DELETE /api/v1/crates/{crate}/{version}/yank` e atualiza `yanked` no índice. O projeto com `Cargo.lock` existente continua compilando com `--locked`; um projeto novo e sem lockfile não resolve a única versão yankada.
5. Um cliente separado com token aleatório inválido recebe 401 no index protegido e não baixa conteúdo. O teste conta index/download/publish/yank e falha para rotas não esperadas; valores de credencial não entram em logs. A fixture converte o metadata de publicação para o formato de index do Cargo; não é código do produto.

## Verificação observada

- `GOPROXY=off GOSUMDB=off GOMAXPROCS=4 go test -timeout=8m -tags=integration -count=3 -v ./internal/spikes/cargoregistry` passou 3/3.
- `GOPROXY=off GOSUMDB=off GOMAXPROCS=4 go test -race -timeout=8m -tags=integration -count=1 -v ./internal/spikes/cargoregistry` passou.
- `GOPROXY=off GOSUMDB=off GOMAXPROCS=4 go vet -tags=integration ./internal/spikes/cargoregistry` passou.

## Limites e trabalho obrigatório

- Um toolchain Cargo/Rust, Linux/amd64; não comprova MSRV, Cargo antigo, Windows/macOS, outros credential providers nem compatibilidade com Git index (deliberadamente não exercitado).
- Auth é sintética no protocolo local. Não comprova emissão/escopo/rotação de tokens, autenticação do produto, autorização por workspace/repository, aprovação, quotas, reserva concorrente de versão ou auditoria.
- A API da fixture não verifica todo o contrato de publish Cargo nem valida pacotes hostis com parser de produção; precisa de testes negativos específicos (malformed framing, dependências/alias, feature metadata, checksum, crate archive, versão duplicada e falha parcial).
- Não exercita CLI `cargo login`, `cargo package`, owner endpoints, unyank, download público/privado misto, redirects/cache distribuído, TLS/proxy confiável, offline completo da instalação nem recuperação/backup.
- A política de yank é demonstrada para uma versão já fixada em lockfile versus resolução nova, não para todos os grafos, workspaces ou comportamento de atualização de cliente.
- A fase Cargo ainda exige adapter produtivo, integração à policy/RBAC e ao fluxo de recebimento/review/publicação, index consistente com storage, idempotência/concorrência, restore, clientes/toolchains/plataformas suportados e evidência de rede/egress.

Esse spike demonstra o caminho de protocolo necessário para continuar a fase 0. Não marca Cargo, a fase 0 ou a v1 como concluídos.
