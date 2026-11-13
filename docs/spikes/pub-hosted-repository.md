# Spike 0.22 — contrato de cliente Pub Hosted Repository

**Data:** 13/10/2026

**Estado:** `dart pub` 3.13.5 publicou e consumiu pacotes sintéticos por uma fixture local compatível com Hosted Pub Repository API v2, incluindo dependência privada transitiva, token via variável de ambiente e rejeição/remoção de token inválido. É uma caracterização de cliente, não adapter, servidor nem suporte de produto. TLS de produção, autorização/RBAC e operação continuam sem prova; fase 0 e v1 não estão concluídas.

## Fixture e execução

O teste `internal/spikes/pubregistry/registry_integration_test.go` inicia um servidor Go em loopback, porta dinâmica e estado efêmero. Usa somente pacotes e valores sintéticos, limite de archive de 8 MiB, cache Pub e diretório XDG separados sob `t.TempDir()` com permissões restritas. O ambiente dos subprocessos não herda variáveis arbitrárias: proxies apontam para uma porta local sem listener, `NO_PROXY` só permite loopback e o grafo de dependências não usa pub.dev.

O cliente de autenticação Pub exige HTTPS para URLs comuns. A SDK temporária gerada para a fixture HTTPS não foi reconhecida pelo runtime Dart, então o contrato usa explicitamente a exceção de desenvolvimento `http://localhost` aceita pelo cliente. Nenhum token real é usado e o listener fica vinculado a `127.0.0.1`; isso **não** testa TLS, terminação TLS, proxy confiável ou envio de credenciais por HTTPS em produção.

```sh
PUB_TEST_DART_BIN=/path/to/dart \
  GOMAXPROCS=4 GOPROXY=off GOSUMDB=off \
  go test -tags=integration -count=3 ./internal/spikes/pubregistry

PUB_TEST_DART_BIN=/path/to/dart \
  GOMAXPROCS=4 GOPROXY=off GOSUMDB=off \
  go test -race -tags=integration -count=1 ./internal/spikes/pubregistry
```

Baseline exercitado: Dart SDK 3.13.5, Linux amd64. A integração requer que esse SDK esteja no `PATH` ou seja indicado por `PUB_TEST_DART_BIN`; não baixa toolchains. Não exercita o wrapper `flutter pub` nem Windows/macOS.

## Evidência observada

- Sem token, `dart pub get` recebe `401` e exibe o texto sintético de `WWW-Authenticate`.
- Um token inválido via `dart pub token add --env-var` resulta em `401`; o cliente remove sua referência do `pub-tokens.json` isolado.
- O token válido é gerado aleatoriamente e passado ao subprocesso apenas via ambiente; a configuração Pub retém a referência à variável, não o valor do segredo.
- `dart pub publish --force` publicou dois pacotes por `GET /api/packages/versions/new`, POST multipart limitado e GET de finalização. A fixture valida `pubspec.yaml` sintético antes de torná-los visíveis.
- O cliente solicitou API v2 (`Accept`) e identificou-se como `Dart pub 3.13.5`. `pub get` baixou os archives, verificou `archive_sha256`, resolveu parent e leaf privados e `dart run bin/main.dart` executou o resultado `parent/private-leaf-value`.
- Teste focalizado passou com `-count=3` e `-race -count=1`. Isso prova apenas o fluxo sintético exercitado.

## Limites e trabalho obrigatório

- Não há implementação do registry, persistência, autorização de produto, RBAC, workspace/repository, rate limit, quotas, audit log, storage, backup ou recuperação.
- Não foram testados `403` para token válido sem permissão, concorrência de versões, idempotência, reupload, publicação pendente/aprovação, revogação durante upload, retract/discontinue/yank, advisories nem operação com cache/CDN.
- O parser da fixture só extrai o pequeno `pubspec.yaml` sintético necessário ao teste; não é validador seguro de archives nem parser Pub para produção.
- O transporte usa HTTP apenas em loopback sintético. TLS e encaminhamento seguro de bearer token são requisitos de produção ainda abertos.
- Um baseline Linux amd64 não demonstra a matriz de SDK/Flutter, Windows/macOS pedida para a CLI de publicação, nem compatibilidade com todos os clientes Pub.
- A fixture não é prova de operação sem egress do produto. O egress deny-by-default continua requisito da instalação.

A especificação contratual usada é [Hosted Pub Repository Specification v2](https://github.com/dart-lang/pub/blob/master/doc/repository-spec-v2.md). Antes de aceitar Pub como formato entregue, implementar e validar os limites acima, especialmente HTTPS/authz, aprovação/concorrência, recuperação e matriz de clientes/plataformas.
