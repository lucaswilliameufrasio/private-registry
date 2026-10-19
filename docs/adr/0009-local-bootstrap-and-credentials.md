# ADR 0009 — Bootstrap local e credenciais

- **Status:** Aceito; login/MFA local interno parcial; exposição HTTP permanece pendente
- **Data:** 2026-10-16

## Contexto

A instalação precisa de um primeiro administrador mesmo em rede isolada, sem tornar público um endpoint de bootstrap nem depender de SMTP/IdP. O plano exige conta local e Argon2id; ADR 0004 proíbe usar email como chave de identidade ou fazer auto-link. O usuário definiu que a conta inicial exige username e email.

## Decisões

- O operador executa `registry bootstrap-admin` no host, depois de aplicar `registry migrate` explicitamente. Bootstrap exige stdin/stdout ligados a TTY; username, nome, email e senha são solicitados interativamente. A senha é digitada sem eco, confirmada, nunca aceita em argumento/env e nunca impressa/logada.
- Username é o identificador de login local, único por instalação, normalizado para lowercase ASCII e limitado a 3–63 caracteres `[a-z0-9._-]`, começando/terminando alfanumérico. Ele é armazenado junto à credencial local, separado da identidade de domínio e do email.
- O primeiro administrador exige email válido e username. Email permanece não verificado, é apenas contato e não requer entrega de email no bootstrap. Email não é usado como login, chave federada ou condição de vínculo; contas locais posteriores podem seguir a política de email do plano.
- Senha deve ter 15–1024 pontos de código Unicode, sem caracteres de controle. Persistir somente Argon2id, formato versionado com parâmetros no hash, salt aleatório de 16 bytes, hash de 32 bytes, memória 64 MiB, 3 iterações e paralelismo 1. Não aparar nem normalizar a senha.
- Em uma transação serializada pelo registro singleton da instalação: verificar que nenhum administrador da instalação existe e inserir usuário, hash local, papel inicial e evento de auditoria. Uma segunda execução falha sem alterar dados. Falha em qualquer inserção faz rollback completo.
- O evento registra o ator como `operator` e o rótulo da conta do processo local; não atribui falsamente a ação ao usuário recém-criado. Auditoria local continua alterável pelo operador privilegiado do host/banco.
- O comando não inicializa schema, não inicia servidor/listener e não cria endpoint HTTP. Se migrations necessárias não estiverem aplicadas, falha com instrução explícita para executar `registry migrate`.

## Alternativas rejeitadas

- **Endpoint HTTP/token temporário:** aumenta superfície pública e introduz corrida/expiração/consumo do segredo; contrário à fronteira local escolhida.
- **Senha em flag, stdin redirecionado ou variável de ambiente:** pode persistir em process list, shell history, logs ou automação; exige terminal sem eco.
- **Email como username ou chave de vínculo:** email é mutável e pode colidir; username separado permite login local sem transformá-lo em identidade federada.
- **Criar admin e credencial em transações separadas:** poderia deixar uma instalação sem credencial utilizável ou com privilégio sem auditoria; rejeitado.

## Consequências e limites

- Migration v3 adiciona credenciais locais e representação de ator externo na auditoria, preservando os eventos existentes como ações de usuários.
- A CLI de bootstrap continua separada do servidor. `internal/auth` agora verifica localmente essas credenciais e conduz o estágio inicial de MFA; isso ainda não implementa login HTTP, cookies, CSRF de navegador, convite ou middleware. Nenhuma rota protegida deve ser exposta antes de origem, sessão, CSRF, limites, MFA e autorização estarem conectados e testados.
- Parâmetros Argon2id são versionados por registro para permitir rehash futuro; custo deve ser medido nas plataformas suportadas antes do aceite operacional.

## Evidência

- [Plano — bootstrap e métodos humanos](../development-plan.md#8-autenticação-humana-e-cadastro)
- [ADR 0004 — identidade OIDC e SCIM](0004-authentication-and-scim-identity.md)
- [ADR 0008 — identidade e workspaces](0008-identity-and-workspace-foundation.md)
