# ADR 0002 — URLs públicas e fronteiras de origem

- **Status:** Aceito como direção de deployment; hosts/domínios concretos são configuração por instalação
- **Data:** 2026-10-12

## Contexto

Os formatos têm roteamento próprio e alguns downloads podem servir HTML, JavaScript, SVG ou outros arquivos controlados por publicadores. Servir esse conteúdo na mesma origem que a sessão administrativa pode permitir execução de conteúdo hostil com autoridade do registry. OCI também tem challenge/token e semântica de namespace distintas dos endpoints de pacote.

## Decisão

- A UI/API administrativa usa uma origem de registry canônica configurada por instalação. A API administrativa fica sob `/api/v1/`.
- Endpoints Pub, Go, Cargo, npm e Hex podem usar paths dedicados nessa origem, respeitando as rotas reais dos clientes; seus caminhos internos são contratos de adapter, não uma API universal.
- OCI usa uma origem pública própria, atrás do gateway confiável. O motor OCI nunca é exposto diretamente; o gateway resolve workspace/repository/image e exige autorização atual.
- Assets executáveis e documentação enviados por usuários usam origem distinta da UI/API administrativa. Cookies de sessão são host-only e não são enviados à origem de assets. CORS e políticas de cache são explícitos e restritos.
- A instalação valida URL externa canônica, TLS e proxies confiáveis. `Forwarded`/`X-Forwarded-*` só são aceitos dos proxies configurados; headers arbitrários não definem host, esquema, IP, redirect URI ou link de recuperação.
- `example.com` nos documentos é ilustrativo. Não há domínio comercial, DNS, certificado ou host fixo escolhido por este ADR.

## Alternativas consideradas

- **Uma única origem para administração e assets:** rejeitada por risco de execução de conteúdo controlado pelo usuário junto à sessão administrativa.
- **Expor diretamente o motor OCI:** rejeitada porque permite contornar autorização central, política, quotas, bloqueios e auditoria.
- **Criar um host por ecossistema:** não necessário para a primeira instalação; paths dedicados sob a origem canônica mantêm configuração simples, sem alterar os contratos nativos.
- **Confiar nos headers de proxy recebidos:** rejeitada porque clientes externos poderiam forjar URL canônica, redirects ou endereço de origem.

## Consequências e trabalho restante

- Deployment e configuração precisam validar todas as origens e impedir aliases ambíguos ou fallback de SPA sobre endpoints de protocolos.
- A fronteira HTTP inicial valida a origem HTTPS canônica e o Host, emite cookies `__Host-` e aplica `nosniff`/`no-store` nas respostas de autenticação; ainda faltam CSP, UI, CORS e teste de isolamento entre UI e conteúdo.
- `serve` exige `REGISTRY_TRUSTED_PROXIES` para o proxy que termina TLS; `X-Forwarded-Proto: https` desse peer é aceito somente como asserção de transporte HTTPS. A origem continua fixa pela configuração e o Host recebido deve corresponder a ela; `Forwarded` e `X-Forwarded-Host` não definem host/origem. Apenas `X-Forwarded-For` de peer confiável participa do rate limit.
- Roteamento real continua condicionado aos testes com clientes de cada formato; estes exemplos não anunciam compatibilidade.
- Pre-signed links têm a janela de revogação do storage documentada e não substituem autorização do gateway por padrão.
- Atualizar este ADR se SSR, frontend em outra origem, CDN, múltiplos hosts por ecossistema ou modo de servir assets mudar a fronteira de segurança.

## Referências

- [Plano — endpoints e domínios](../development-plan.md#42-endpoints-e-domínios)
- [Plano — assets e links privados](../development-plan.md#77-artefatos-genéricos-e-assets)
- [Modelo de ameaças inicial](../threat-model.md)
