# ADR 0052 — Interface web embutida

- **Status:** Implementado; cobre as tarefas do dia a dia, não toda a API
- **Data:** 2026-11-12

## Decisão

Seguindo a direção do plano (frontend estático embutido, sem servidor Node separado), a interface é HTML, CSS e JavaScript simples em `internal/webui/static`, embutidos no binário com `go:embed`, sem etapa de build e sem código de terceiros. É servida em `/` e `/ui/*` somente na origem canônica e por HTTPS; a origem de assets nunca a serve. Ela usa a mesma API dos demais clientes, então sessão, CSRF, origem e MFA recente valem igual.

Cabeçalhos: CSP `default-src 'none'; script-src 'self'; style-src 'self'; img-src 'self' data:; connect-src 'self'; base-uri 'none'; form-action 'self'; frame-ancestors 'none'`, sem script inline; `X-Frame-Options: DENY`, `nosniff`, `Referrer-Policy: no-referrer`, `Cross-Origin-Opener-Policy: same-origin`. Todo texto vindo do servidor entra no DOM como texto, nunca como HTML.

Telas: entrar (senha com TOTP ou cadastro de TOTP, passkey, Muira), workspaces, repositórios (criação com formato, instruções de cliente, tokens próprios, acesso/grants, CI com contas de serviço e trusted publishers, revisões OCI), membros, convites, contas de serviço, conta (TOTP, passkeys) e administração (política de cadastro, estado da replicação, link de recuperação), além das páginas públicas de aceitar convite e de recuperar acesso.

Endpoints novos de apoio: `GET /api/v1/auth/methods` (métodos de login disponíveis, sem sessão), `GET /api/v1/auth/session` (quem está logado e em que nível) e `GET /api/v1/workspaces/{w}/members` (membros ativos, para qualquer membro). O callback do Muira redireciona de volta para a interface quando é uma navegação do navegador.

## Limites

Não cobre política de visibilidade, quotas, tags imutáveis e exclusões OCI, revisões de Cargo/npm/Pub, jobs de manutenção nem a API de artefatos genéricos; esses continuam pela API. Sem internacionalização (só português). Não há QR code do TOTP: a chave e a URL `otpauth://` aparecem em texto.

## Evidência

Teste HTTP de cabeçalhos, caminhos e origem. `TestWebInterfaceInARealBrowser` (opt-in com `BROWSER_TEST_CHROMIUM`) sobe o `serve` atrás de TLS e conduz o Chromium headless pelo DevTools Protocol: login com senha, cadastro de TOTP com código calculado, códigos de recuperação, criação de workspace e repositório npm, grant, emissão e listagem de token, convite, cadastro de passkey com o autenticador virtual do Chromium, logout e login só com a passkey em sessão MFA, e a página de administração. Passou três vezes com race. A execução encontrou e corrigiu três defeitos que os testes HTTP não pegariam.
