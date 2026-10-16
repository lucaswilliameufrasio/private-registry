# Spike 0.19 — cliente Go contra fixture de proxy de módulos

**Data:** 12/10/2026

**Estado:** Go 1.27.1 linux/amd64 consumiu módulo privado v2 e dependência transitiva por proxy HTTP local; não é adapter de produção nem aceite do formato Go.

## Reprodução e isolamento

```sh
GOMAXPROCS=4 GOPROXY=off GOSUMDB=off go test -tags=integration -count=3 -v ./internal/spikes/gomodproxy
```

O teste usa o `go` nativo do ambiente (1.27.1 linux/amd64), módulos e conteúdo sintéticos `example.com/private/...`, servidor HTTP ligado a loopback e caches/`HOME` temporários. O subprocesso define `GOTOOLCHAIN=local`, `GOWORK=off`, `GOENV=off`, `GOPRIVATE=example.com/private`, `GONOPROXY=none` e `GONOSUMDB=example.com/private`. Seu único `GOPROXY` é o servidor local; ausência de caminho responde 404 sem fallback público. O processo consumidor não recebe `GOSUMDB=off`; a exclusão de checksum database é específica ao namespace private.

Não há credenciais, variáveis de proxy herdadas, dependências públicas, pulls de imagens ou contato com produção. Cada repetição cria e limpa workspace/cache próprios, inclusive diretórios de módulo read-only deixados pelo cliente Go.

## Contrato exercitado

1. Proxy fornece `@v/list`, `.info`, `.mod` e `.zip` de `example.com/private/parent/v2` nas versões `v2.0.0` e `v2.1.0`, além de dependências transitivas `leaf` e `example.com/private/Upper`.
2. `go mod tidy`, `go mod download all` e `go run .` consomem o parent v2 e compilam/avaliam a dependência transitiva sem buscar conteúdo público.
3. `go list -m -versions` lê a lista de versões; `go get .../v2@latest` seleciona `v2.1.0`; a execução posterior confirma o conteúdo atualizado.
4. Outro módulo sintético tem lista vazia e endpoint `@latest`, exercitando a seleção via endpoint específico. O cliente também faz probes de `@v/list` para prefixos de caminho ao descobrir o módulo; esses paths conhecidos retornam 404 local e não são encaminhados a outro proxy.
5. Um import transitivo com letra maiúscula comprova o path HTTP escapado (`!upper`) e a raiz ZIP no módulo original sem escaping, conforme o cliente Go. O teste inspeciona requests, exige os recursos esperados, rejeita paths inesperados e headers Authorization ambientados.

## Limites

- Uma versão de Go, em Linux/amd64; não comprova a linha anterior mantida, Windows/macOS nem compatibilidade multiplataforma da CLI do registry.
- Apenas leitura pelo protocolo `GOPROXY`; sem API/CLI de publicação, validação de ZIP do lado registry, checksum metadata `sumdb`, pseudo-versions, matriz completa de escaping/case, descoberta `?go-get=1`, cache misto público/privado ou teste de fallback em proxy corporativo.
- O servidor é fixture de protocolo, não código do registry; não prova autenticação, autorização, isolamento, imutabilidade, storage, auditoria, quota ou aprovação humana.
- O escopo Go v1 ainda requer módulos privados transitivos, major v2, ausência de vazamento em configuração mista, empacotamento/publicação pela fonte, validação com `golang.org/x/mod` e testes de instalação/restore.

## Verificação

`GOPROXY=off GOSUMDB=off GOMAXPROCS=4 go test -timeout=3m -tags=integration -count=3 -v ./internal/spikes/gomodproxy` passou três vezes com Go 1.27.1. As tentativas iniciais corrigiram a fixture, não o contrato: o cliente exige `go mod tidy` para registrar dependência transitiva no grafo, faz descoberta de prefixos, escapa letras maiúsculas no endpoint (`!upper`) mas mantém o module path original dentro do ZIP, e usa `@latest` quando a lista está vazia. Ainda não foi executado `make verify` depois destas alterações.

Esta é evidência de fase 0, não suporte Go anunciado nem conclusão da fase ou da v1.
