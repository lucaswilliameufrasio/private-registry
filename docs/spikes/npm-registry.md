# Spike 0.21 — cliente npm contra registry privado com scope

**Data:** 13/10/2026

**Estado:** Node.js 24.21.0/npm 11.19.0 reais publicaram e instalaram dois pacotes privados scoped, validaram integrity e moveram dist-tag em registry HTTP local. Não é adapter nem suporte npm de produção.

## Reprodução e isolamento

```sh
GOMAXPROCS=4 GOPROXY=off GOSUMDB=off go test -tags=integration -count=3 -v ./internal/spikes/npmregistry
GOMAXPROCS=4 GOPROXY=off GOSUMDB=off go test -race -tags=integration -count=1 ./internal/spikes/npmregistry
```

O teste exige exatamente Node.js 24.21.0 e npm 11.19.0. Usa scope e conteúdo sintéticos, servidor preso a loopback, workspace/cache/npmrc temporários e token aleatório no user config com modo `0600`, scoped ao host/porta local. A fixture não imprime credenciais. HTTP(S) proxy aponta para loopback porta 9, com `NO_PROXY` apenas para localhost; registry/audit externos não são usados. Instalações usam `--ignore-scripts`, `--no-audit` e `--no-fund`.

## Contrato exercitado

1. `npm publish` publica pacote leaf e pacote parent scoped por `PUT` do metadata/attachment; a fixture valida framing JSON, nome/versão, tarball gzip e `package.json` interno.
2. A fixture materializa packument com versões, `exports`, tipos, dependências, dist-tags e URLs de download; calcula SHA-1 compatível com `shasum` e SHA-512 SRI do `.tgz`.
3. Um npm cache separado evita reutilizar os bytes do publish; `npm install --package-lock-only` seguido de `npm ci` busca os tarballs privados e resolve uma dependência transitiva scoped. A execução Node comprova o código carregado e npm valida `integrity`.
4. `npm dist-tag add ... next` lê/atualiza dist-tags pela API compatível; `npm view ... dist-tags` observa a atualização.
5. A fixture exige token nas rotas exercitadas e rejeita métodos/paths inesperados. O token vale apenas para este teste; não há usuário real, ACL ou papéis.

## Verificação observada

- `GOPROXY=off GOSUMDB=off GOMAXPROCS=4 go test -timeout=8m -tags=integration -count=3 -v ./internal/spikes/npmregistry` passou 3/3.
- `GOPROXY=off GOSUMDB=off GOMAXPROCS=4 go test -race -timeout=8m -tags=integration -count=1 -v ./internal/spikes/npmregistry` passou.
- `GOPROXY=off GOSUMDB=off GOMAXPROCS=4 go vet -tags=integration ./internal/spikes/npmregistry` passou.

## Limites e trabalho obrigatório

- Uma versão de Node/npm, Linux/amd64. pnpm, Yarn, Bun, Windows/macOS e matriz de versões permanecem sem evidência.
- A fixture não comprova autorização por usuário/workspace, token scopes, ACL para mover dist-tags, aprovação/review, version reservation concorrente, idempotência sob retry ou política de exclusão/quarentena.
- Não testa dependências externas/lockfile misto, npm login/logout, redirects, proxy/TLS confiável, auditoria, recuperação, cache compartilhado nem cliente SvelteKit real. O pacote preserva `exports`/`types`, mas não é componente Svelte compilado.
- Parser de tarball e validação de metadata são mínimos e exclusivos da fixture; não são hardened nem devem ser reutilizados como implementação do produto.
- Não comprova instalação offline completa, backup/restore, storage S3/filesystem, egress policy do servidor ou consistência entre banco/packument/tarball.

Esse spike é evidência de contrato para continuar a fase 0. Não conclui a fase npm, a fase 0 ou a v1.
