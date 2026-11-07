# ADR 0020 — Serving público inicial de assets genéricos

- **Status:** Fatia inicial; cache público e documentação interativa pendentes
- **Data:** 2026-11-07

## Contexto e decisão

O plano exige URLs de arquivos genéricos em origem de assets distinta da administração. Repositórios `listed` ou `unlisted` só se tornam acessíveis anonimamente quando configurados explicitamente; o padrão continua privado. Esta fatia acrescenta `GET`/`HEAD /public/{workspace-slug}/{repository-slug}/{collection}/{version}/{path...}` exclusivamente na origem de assets configurada.

- Uma única consulta resolve workspace/repositório ativos, visibilidade pública, versão publicada e arquivo exato. Caminho inválido, recurso inexistente e conteúdo privado retornam o mesmo 404; o storage não é aberto antes dessa verificação. A abertura repete a consulta para reduzir a janela entre resolução e leitura. Uma leitura já autorizada pode terminar após uma mudança de visibilidade; cópias externas não podem ser recolhidas.
- GET/HEAD suportam ETag e Range único. A resposta usa MIME declarado, `nosniff`, `Content-Disposition: inline` e origem separada; HTML navegável continua sujeito a `CSP sandbox; default-src 'none'` e `X-Frame-Options: DENY`. Isso permite uso inicial de JS/CSS como recursos externos, mas não promete documentação HTML interativa nem scripts de módulo cross-origin.
- Usar `Cache-Control: no-store`; CORS fica desligado por padrão e pode ser habilitado por allowlist de até 32 origens HTTPS exatas em `REGISTRY_PUBLIC_ASSET_CORS_ORIGINS`, com restart. A regra é global para assets públicos, não se aplica a tickets privados e nunca permite credenciais. Preflight admite somente GET/HEAD e os headers Range/If-Range/If-None-Match; não há wildcard. Isso é deliberadamente mais restrito do que o cache público longo planejado; não anunciar suporte a CDN ou ao aceite integral do bundle por essa fatia.
- O endpoint não retorna listagens ou pesquisa, não altera a API de tickets privados e não muda o comportamento de visibilidade de repositórios existentes. Clientes não devem tratar `unlisted` como segredo.

## Limites

Continuam obrigatórios políticas de CORS mais granulares, cache público/invalidação e demonstração de Scalar/widget completos, além de autorização e métricas dos demais formatos. O isolamento de origem depende também de deployment TLS/proxy correto; não serve como sandbox entre todos os publicadores de uma mesma origem. Ver [ADR 0002](0002-public-url-and-origin-boundaries.md) e [ADR 0016](0016-generic-artifact-publication.md).
