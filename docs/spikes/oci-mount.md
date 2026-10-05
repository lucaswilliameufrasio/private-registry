# Spike 0.8 — cross-repository mount e alcance publicado OCI

**Data:** 05/10/2026

**Estado:** comportamento nativo e gate experimental exercitados. Não implementa gateway/RBAC ou aceite OCI de produção.

## Reprodução

```sh
GOMAXPROCS=4 make setup-oci
GOMAXPROCS=4 go test -tags=integration -count=3 -run '^TestOCIMount' -v ./internal/spikes/ociprobe
GOMAXPROCS=4 make verify
```

Distribution 3.1.2 e ORAS 1.3.4 já fixados. Motor em Unix socket privado, proxies apenas loopback, filesystem e dados sintéticos exclusivos. S3 de desenvolvimento permanece Floci; este teste usa storage local OCI.

## Evidência nativa

ORAS publica um artefato na origem; HTTP OCI envia também um blob sem manifest aprovado. No motor de storage sem autenticação, `POST /v2/<destino>/blobs/uploads/?from=<origem>&mount=<digest>` desse blob pendente retorna **201**, com digest esperado. GET no destino retorna **200 e os bytes pendentes exatos**.

Portanto, storage mount não conhece revisão/alcance publicado. Bloquear apenas downloads na origem ou `PUT` de manifest não impede links em outros repositórios. Digest global conhecido não é autorização por workspace/repository.

Mount de digest inexistente retorna **202** (fallback para upload), e o blob continua ausente com GET **404**: 202 não significa mount realizado/publicação. A fixture deixa esse upload vazio para remoção junto de seu storage próprio.

## Gate experimental: duas pontas e estado de publicação

Inputs sintéticos de permissão atual e um descritor publicado conhecido, qualificado pela origem. Testes reais contra o motor exigem:

- Sem leitura na origem ou sem publicação no destino: mount **403**. Ambos ausentes também negam.
- Origem de outro namespace: **403**; `from` duplicado/ambíguo: **400**.
- Blob pendente na origem: **404**, mesmo com ambas as permissões.
- Blob publicado com ambas as permissões: mount real **201**, digest correto, Location reescrita via gateway, bytes efetivamente ligados no storage de destino.
- Destino sem manifest publicado: GET/HEAD de blob montado, seja publicado na origem ou pendente previamente ligado pelo motor, continuam **404** no gateway.
- Download de conteúdo publicado na origem permanece **200**; revogar leitura na origem nega novo mount, mesmo após sucesso anterior.

Mount permitido economiza upload, **não** concede distribuição no destino. Somente publicação válida ali deve acrescentar alcance, sujeito a suas próprias políticas/checks/revisão. Liberação no destino já foi exercitada separadamente no [spike de revisão](oci-review.md), não composta neste teste.

## Limites obrigatórios

Esta fixture de storage não autentica JWT: permissões são flags atômicas para testar a fronteira com o motor real, não usuários, RBAC ou delegação implementados. Prova de JWT está no [spike 0.5](oci-auth.md). Não extrapolar para autorização completa nas duas pontas ou todos os clientes Docker.

O gate limitado rejeita mount de digest fora do seu único descritor publicado. Não implementa fallback autorizado de produção, roteamento geral, canonização completa de paths/queries, inventário global, manifests por digest/referrers/índices ou métodos arbitrários. Não globalizar esse allowlist de teste.

Ainda necessários: projeção durável/reconciliável de alcance por repo, coordenação com commit/revisão/GC/leases, quotas de referências/blobs, revalidação durante a mesma requisição upstream, sessões/tokens atuais e matriz de clientes reais. Motor de storage da fixture pode ser acessado por outro código de teste para caracterização; em produção não pode existir bypass do gateway. ADR/aceite OCI continuam abertos.

## Verificação

`GOPROXY=off GOSUMDB=off GOMAXPROCS=4 make verify` completo passou: build sem CGO, formatação, vet normal/integration, sintaxe Bash, testes sem cache, integrações reais três vezes e race detector. Tools/imagens/caches estavam preparados; não prova instalação offline/egress do produto.

Esta continuação 0.8 é posterior ao commit/push `0b90614`; ainda não está nesse commit.
