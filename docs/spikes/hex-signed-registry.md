# Spike 0.17 — consumo Mix de registry Hex privado assinado

**Data:** 09/10/2026

**Estado:** consumo read-only de registry estático local autenticado e assinado, resolução transitiva e rejeição de metadata adulterada comprovados com Mix/Hex reais. Não é adapter/API de publicação nem suporte Hex de produção.

## Requisitos do teste e reprodução

O teste usa o Mix/Elixir/OTP/Hex fixado para a evidência local: Mix 1.19.5, Elixir 1.19.5, OTP 28.4 e Hex 2.5.1. `make check-hex` falha se o baseline não estiver instalado; não baixa ferramentas nem muda configuração global.

```sh
make check-hex
GOMAXPROCS=4 go test -tags=integration -count=3 -run '^TestMixConsumesAuthenticatedSignedPrivateRegistryAndRejectsTamperedMetadata$' -v ./internal/spikes/hexregistry
GOPROXY=off GOSUMDB=off GOMAXPROCS=4 make verify
```

Fontes consultadas: [Hex self-hosting](https://hex.pm/docs/self-hosting), `mix help hex.registry` e `mix help hex.repo` do toolchain testado. O teste usa `mix hex.build` para produzir tarballs sintéticos e `mix hex.registry build` para gerar `public_key` e registry assinado. A private key RSA de 2048 bits está fora do diretório servido, modo 0600; somente a public key é configurada no cliente.

## Fluxo comprovado

1. Constrói `registry_fixture_leaf` e `registry_fixture_parent` localmente com `mix hex.build`; o parent declara a dependência privada com `repo: "reg-fixture"`.
2. O registry contém os tarballs e os recursos assinados gerados por `mix hex.registry build`; não implementa servidor de autoria. Isso segue o split Hex entre HTTP API de publicação/admin e Repository read-only de entrega.
3. Servidor de fixture limita o listener a `127.0.0.1`, serve somente o diretório `public/` e exige HTTP Basic com credenciais sintéticas em todo GET/HEAD. O cliente usa `HEX_HOME` exclusivo e configura repo/key via `mix hex.repo add`; nenhuma configuração global do operador é alterada.
4. `mix deps.get` resolve o parent e o leaf privado, baixa os tarballs e `mix run` compila/avalia `RegistryFixtureParent.value()` com resultado sintético esperado. O teste confirma pedidos autenticados ao servidor.
5. Para a negativa, altera um byte do payload assinado **depois de descompactar e recomprime gzip válido**, preservando a estrutura externa. Um Mix client limpo busca o mesmo recurso e rejeita-o por assinatura; a assertiva verifica erro de assinatura e GET autenticado do path adulterado, não apenas um exit status genérico.

Observação de compatibilidade: o primeiro teste tentou deixar a dependência do parent sem `repo`; Mix procurou o leaf no registry padrão (`registry`) e a resolução falhou. O fixture final inclui o nome do repo na declaração Hex da dependência. A documentação do consumidor deve instruir como declarar `repo` nas dependências transitivas, ou o produto deve projetar uma política explícita para isso; não assumir herança que o cliente testado não realizou.

`HEX_API_URL` aponta a porta loopback fechada `127.0.0.1:1` e proxies são removidos no subprocesso, para tentativa de API externa falhar localmente. Isso não é uma política de egress do host/produto. Todos os dados, nomes e credenciais são sintéticos; projetos, caches Hex, chaves e portas são exclusivos por execução, com timeout limitado.

## Limites e gaps obrigatórios

- Só consumo de Repository read-only: não prova API autenticada/idempotente de publicação, `mix hex.publish`, criação/transição de metadata, aprovação humana ou CLI/API de upload do tarball.
- Não implementa server Hex, ACL por workspace/repository, isolamento de namespace, lifecycle/version immutability, quotas, digest/storage adapter, retenção, backup/restore de chave ou rotação com clientes existentes.
- Não testa Authentik/SCIM, clientes Hex em outras versões, Rebar3, distribuição de docs, Hex organization/policy, certificados TLS, proxy/reverse-proxy, caches ou autenticação com token/chave alternativa.
- O listener usa HTTP loopback e Basic Auth sintético; não prova TLS, gestão de credenciais real, rede isolada ou deny-by-default/allowlist de egress.
- A chave/registry é gerada pela task oficial Mix na fixture. Isso prova que o cliente Mix rejeita metadata assinada adulterada, não que o registry futuro produza corretamente todos os recursos, publique consistentemente nem preserve chaves em backup.
- É apenas uma evidência de fase 0. Não anunciar Hex como suportado e não marcar fase 0/v1 concluída.

## Verificação

O teste focado passou três vezes, e `GOPROXY=off GOSUMDB=off GOMAXPROCS=4 make verify` passou com build, gofmt, vet, unit, integrações, Mix/Hex e race detector. O ambiente já tinha Elixir/Mix/Hex instalados; isso não comprova instalação offline do produto.
