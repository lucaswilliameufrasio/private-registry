# ADR 0011 — Autenticação humana, MFA e sessões

- **Status:** Contrato aceito; endpoints e middleware ainda não implementados
- **Data:** 2026-10-18

## Contexto

O bootstrap local já cria a identidade inicial, mas não existe login nem superfície protegida. Autenticação, fatores, recuperação e revogação precisam ser definidos antes de expor rotas administrativas ou de conteúdo. O sistema deve continuar utilizável offline, respeitar identidade estável do ADR 0004 e permitir bloqueio efetivo de sessões quando uma conta é desativada.

## Decisões

- Username é o identificador do login local; senha usa Argon2id conforme ADR 0009. OIDC autentica por `(provider_id, issuer, subject)` e email não vincula contas automaticamente.
- MFA é obrigatório por padrão para administradores da instalação e proprietários/administradores de workspace. TOTP, passkeys e códigos de recuperação são requisitos da v1; a chave e o envelope TOTP seguem ADR 0010. Administradores sem fator ativo não recebem sessão privilegiada: o fluxo futuro deve conduzir por uma etapa restrita de cadastro/confirmação do fator.
- O seed TOTP só se torna ativo depois de confirmação com código válido. Códigos de recuperação são mostrados uma única vez, armazenados como hashes e consumidos uma vez. Recuperação não equivale a reset de MFA; reset não concede sessão e exige comprovação/autorização, justificativa, auditoria e novo cadastro do fator.
- A sessão humana é opaca, aleatória, persistida de forma revogável e armazenada no banco somente como hash do bearer. Login, MFA bem-sucedido e elevação de privilégio rotacionam a sessão; logout revoga a sessão no servidor. Estado ativo/bloqueado da conta e revogação precisam ser reavaliados em cada request protegido, sem confiar em logout federado.
- Duração padrão: 12 horas absolutas e 1 hora de inatividade. A atividade pode renovar o limite inativo, nunca o absoluto. Operações sensíveis exigem reautenticação recente.
- O cookie é host-only, sem `Domain`, `Secure`, `HttpOnly`, `SameSite=Lax`, `Path=/` e prefixo `__Host-`. A UI/API usa a origem canônica do ADR 0002; headers de proxy só são confiáveis quando enviados por proxies configurados.
- Requests de navegador com efeitos de escrita exigem defesa CSRF e validação de `Origin` contra a origem canônica. `SameSite` é defesa adicional, não substitui CSRF. CORS permanece restrito; cookies de sessão não são enviados à origem separada de assets.
- Login, MFA e recuperação exigem limites de tentativas e respostas que não enumerem contas. A implementação não deve expor rotas até sessão, CSRF, origem, revogação, MFA e testes de autorização estarem conectados ao router.

## Alternativas rejeitadas

- **Sessão stateless sem persistência de revogação:** não permite bloqueio efetivo após logout, suspensão/SCIM ou incidente; rejeitado.
- **Guardar bearer de sessão ou seed TOTP em claro no banco:** amplia o impacto de dump/snapshot; rejeitado.
- **Email como segundo fator ou método de vínculo:** não atende o contrato de identidade/MFA e depende de entrega externa; rejeitado como substituto de TOTP/passkey.
- **Confiar somente em `SameSite` ou logout OIDC:** não cobre CSRF nem invalidação local de sessões; rejeitado.

## Consequências e limites

- As entregas seguintes deverão implementar login, enrollment/confirmação TOTP, códigos de recuperação, sessões revogáveis, cookies e CSRF em fatias testadas, sem liberar conteúdo até autorização independente estar pronta.
- Passkeys continuam obrigatórias para v1; uma passkey só satisfaz a política MFA quando o autenticador comprova user verification, não apenas presença/toque.
- Ainda não existem mecanismos de limite de tentativas, sessão, MFA, reset/recuperação, middleware ou rotas protegidas. Este ADR não anuncia autenticação utilizável.

## Referências

- [Plano — autenticação humana e cadastro](../development-plan.md#8-autenticação-humana-e-cadastro)
- [ADR 0002 — URLs públicas e fronteiras de origem](0002-public-url-and-origin-boundaries.md)
- [ADR 0004 — identidade OIDC e SCIM](0004-authentication-and-scim-identity.md)
- [ADR 0009 — bootstrap local e credenciais](0009-local-bootstrap-and-credentials.md)
- [ADR 0010 — chave mestra local e envelopes](0010-local-master-key-and-secret-envelopes.md)
- [Modelo de ameaças inicial](../threat-model.md)
