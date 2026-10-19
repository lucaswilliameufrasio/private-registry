# ADR 0011 — Autenticação humana, MFA e sessões

- **Status:** Contrato aceito; login/TOTP/sessões internos parciais; endpoints e middleware ainda não implementados
- **Data:** 2026-10-18

## Contexto

O bootstrap local já cria a identidade inicial e serviços internos agora verificam credenciais, mas não há login nem superfície protegida expostos pelo produto. Autenticação, fatores, recuperação e revogação precisam ser definidos antes de expor rotas administrativas ou de conteúdo. O sistema deve continuar utilizável offline, respeitar identidade estável do ADR 0004 e permitir bloqueio efetivo de sessões quando uma conta é desativada.

## Decisões

- Username é o identificador do login local; senha usa Argon2id conforme ADR 0009. OIDC autentica por `(provider_id, issuer, subject)` e email não vincula contas automaticamente.
- MFA é obrigatório por padrão para administradores da instalação e proprietários/administradores de workspace. TOTP, passkeys e códigos de recuperação são requisitos da v1; a chave e o envelope TOTP seguem ADR 0010. Administradores sem fator ativo não recebem sessão privilegiada: o fluxo interno atual os conduz por uma etapa restrita de cadastro/confirmação do fator.
- O seed TOTP só se torna ativo depois de confirmação com código válido. Códigos de recuperação são mostrados uma única vez, armazenados como hashes e consumidos uma vez. Recuperação não equivale a reset de MFA; reset não concede sessão e exige comprovação/autorização, justificativa, auditoria e novo cadastro do fator.
- A sessão humana é opaca, aleatória, persistida de forma revogável e armazenada no banco somente como hash do bearer. Login, MFA bem-sucedido e elevação de privilégio rotacionam a sessão; logout revoga a sessão no servidor. Estado ativo/bloqueado da conta e revogação precisam ser reavaliados em cada request protegido, sem confiar em logout federado.
- Duração padrão: 12 horas absolutas e 1 hora de inatividade. A atividade pode renovar o limite inativo, nunca o absoluto. Operações sensíveis exigem reautenticação recente.
- O cookie é host-only, sem `Domain`, `Secure`, `HttpOnly`, `SameSite=Lax`, `Path=/` e prefixo `__Host-`. A UI/API usa a origem canônica do ADR 0002; headers de proxy só são confiáveis quando enviados por proxies configurados.
- Requests de navegador com efeitos de escrita exigem defesa CSRF e validação de `Origin` contra a origem canônica. `SameSite` é defesa adicional, não substitui CSRF. CORS permanece restrito; cookies de sessão não são enviados à origem separada de assets.
- Login, MFA e recuperação exigem limites de tentativas e respostas que não enumerem contas. A implementação não deve expor rotas até sessão, CSRF, origem, revogação, MFA e testes de autorização estarem conectados ao router.
- Defaults operacionais: no máximo 5 tentativas por conta e 20 por IP em janela móvel de 15 minutos, sem bloqueio permanente; IP é derivado do peer de rede, e headers de forwarding só podem vir de proxy configurado. Limites são compartilhados entre login e MFA por IP; a conta tem bucket próprio por senha e por MFA. O estado guarda só hashes dos identificadores e timestamps recentes, expira após a janela, tem teto de 50.000 buckets e nega novas entradas quando cheio. Argon2 permite no máximo duas derivações concorrentes no processo e rejeita trabalho excedente sem fila.

## Alternativas rejeitadas

- **Sessão stateless sem persistência de revogação:** não permite bloqueio efetivo após logout, suspensão/SCIM ou incidente; rejeitado.
- **Guardar bearer de sessão ou seed TOTP em claro no banco:** amplia o impacto de dump/snapshot; rejeitado.
- **Email como segundo fator ou método de vínculo:** não atende o contrato de identidade/MFA e depende de entrega externa; rejeitado como substituto de TOTP/passkey.
- **Confiar somente em `SameSite` ou logout OIDC:** não cobre CSRF nem invalidação local de sessões; rejeitado.

## Consequências e limites

- Migration v4 e `internal/mfa` implementam parcialmente enrollment TOTP com SHA-1/6 dígitos/30 segundos, janela de confirmação de ±1 passo, confirmação antes da ativação, prevenção de replay, expiração de enrollment em 10 minutos e dez códigos de recuperação aleatórios de uso único armazenados como SHA-256. O seed usa envelope XChaCha20-Poly1305 com AAD específica por usuário. A service não cria sessão nem expõe rotas.
- Migration v5 e `internal/sessions` persistem somente hashes de bearers/CSRF, validam usuário ativo, duração absoluta padrão de 12 horas e inatividade de 1 hora, suportam validação CSRF e rotação/revogação. Contextos pré-autenticados de enrollment MFA expiram em 10 minutos e challenges MFA em 5 minutos.
- Migration v6, `internal/password`, `internal/authattempts` e `internal/auth` integram login local Argon2id, regras que exigem MFA de administradores de instalação/workspace, enrollment TOTP restrito, challenge/recovery e limite persistido. Os serviços são internos: ainda não estão conectados a cookies, origem canônica, CSRF de navegador ou middleware HTTP. O SHA-256 dos identificadores reduz exposição acidental, mas não é criptografia nem protege contra adivinhação offline de username/IP em dump do banco.
- As entregas seguintes deverão conectar login, enrollment, recuperação e TOTP ao router, cookies host-only, origem canônica e CSRF, sem liberar conteúdo até autorização independente estar pronta.
- Passkeys continuam obrigatórias para v1; uma passkey só satisfaz a política MFA quando o autenticador comprova user verification, não apenas presença/toque.
- Ainda não existem login/sessões via HTTP, cookies, validação de Origin, passkeys, reset/recuperação operacional, middleware ou rotas protegidas. As bases internas não anunciam autenticação/MFA utilizável pelo produto.

## Referências

- [Plano — autenticação humana e cadastro](../development-plan.md#8-autenticação-humana-e-cadastro)
- [ADR 0002 — URLs públicas e fronteiras de origem](0002-public-url-and-origin-boundaries.md)
- [ADR 0004 — identidade OIDC e SCIM](0004-authentication-and-scim-identity.md)
- [ADR 0009 — bootstrap local e credenciais](0009-local-bootstrap-and-credentials.md)
- [ADR 0010 — chave mestra local e envelopes](0010-local-master-key-and-secret-envelopes.md)
- [Modelo de ameaças inicial](../threat-model.md)
