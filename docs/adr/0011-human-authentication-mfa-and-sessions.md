# ADR 0011 — Autenticação humana, MFA e sessões

- **Status:** Contrato aceito; login/TOTP/sessões e rotas protegidas de workspace, membership, metadados de repositório e grants conectados; administração geral e serving de conteúdo continuam pendentes
- **Data:** 2026-10-18

## Contexto

O bootstrap local já cria a identidade inicial e serviços internos agora verificam credenciais, mas não há login nem superfície protegida expostos pelo produto. Autenticação, fatores, recuperação e revogação precisam ser definidos antes de expor rotas administrativas ou de conteúdo. O sistema deve continuar utilizável offline, respeitar identidade estável do ADR 0004 e permitir bloqueio efetivo de sessões quando uma conta é desativada.

## Decisões

- Username é o identificador do login local; senha usa Argon2id conforme ADR 0009. OIDC autentica por `(provider_id, issuer, subject)` e email não vincula contas automaticamente.
- MFA é obrigatório por padrão para administradores da instalação e proprietários/administradores de workspace. TOTP, passkeys e códigos de recuperação são requisitos da v1; a chave e o envelope TOTP seguem ADR 0010. Administradores sem fator ativo não recebem sessão privilegiada: o fluxo interno atual os conduz por uma etapa restrita de cadastro/confirmação do fator.
- O seed TOTP só se torna ativo depois de confirmação com código válido. Códigos de recuperação são mostrados uma única vez, armazenados como hashes e consumidos uma vez. Recuperação não equivale a reset de MFA; reset não concede sessão e exige comprovação/autorização, justificativa, auditoria e novo cadastro do fator.
- A sessão humana é opaca, aleatória, persistida de forma revogável e armazenada no banco somente como hash do bearer. Login, MFA bem-sucedido e elevação de privilégio rotacionam a sessão; logout revoga a sessão no servidor. Estado ativo/bloqueado da conta e revogação precisam ser reavaliados em cada request protegido, sem confiar em logout federado.
- Duração padrão: 12 horas absolutas e 1 hora de inatividade. A atividade pode renovar o limite inativo, nunca o absoluto. Operações sensíveis exigem reautenticação recente.
- A criação de workspace, que concede ownership ao ator, exige sessão MFA autenticada há menos de 5 minutos. O limite inicial coincide com a duração do challenge MFA; login com nova verificação MFA emite sessão fresca. Outras operações sensíveis precisam definir e testar seu próprio contrato de reautenticação antes de serem expostas.
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
- Migration v6, `internal/password`, `internal/authattempts` e `internal/auth` integram login local Argon2id, regras que exigem MFA de administradores de instalação/workspace, enrollment TOTP restrito, challenge/recovery e limite persistido. O SHA-256 dos identificadores reduz exposição acidental, mas não é criptografia nem protege contra adivinhação offline de username/IP em dump do banco.
- A fronteira HTTP inclui `POST /api/v1/auth/login`, `POST /api/v1/auth/mfa/enrollment`, `POST /api/v1/auth/mfa/enrollment/start`, `POST /api/v1/auth/mfa/enrollment/complete`, `POST /api/v1/auth/mfa/challenge` e `POST /api/v1/auth/logout`. O início voluntário de enrollment rotaciona uma sessão padrão para uma sessão `enrollment_only` curta antes de retornar o seed. Login retorna apenas o estágio; bearer nunca vai em JSON. Enrollments e recovery codes usam respostas `no-store`.
- A sessão usa cookie `__Host-registry-session` com `Secure`, `HttpOnly`, `SameSite=Lax`, `Path=/` e sem `Domain`. O CSRF usa cookie host-only `__Host-registry-csrf` legível pelo cliente same-origin, enviado também no header `X-CSRF-Token`; o valor é comparado com o cookie e validado contra o hash persistido da sessão. Todo POST exige `Origin` único, HTTPS e igual à origem canônica; o `Host` da requisição também deve corresponder. Login exige Origin mesmo sem sessão prévia.
- `REGISTRY_CANONICAL_ORIGIN` é obrigatório ao executar `serve` e aceita uma origem HTTPS sem path. `REGISTRY_TRUSTED_PROXIES` exige o IP/CIDR do proxy TLS; sem TLS direto, a requisição só é aceita quando esse peer envia exatamente `X-Forwarded-Proto: https`. Essa asserção não define a origem canônica. Somente quando o peer direto pertence à lista confiável, a cadeia `X-Forwarded-For` é percorrida da direita para a esquerda; `Forwarded` e `X-Forwarded-Host` são ignorados. O proxy deve preservar o Host canônico.
- `GET /api/v1/workspaces` valida a sessão em cada request, aceita somente níveis `standard`/`mfa` e retorna memberships ativos da identidade autenticada com paginação keyset; sessões `enrollment_only` e `mfa_challenge` recebem `403 authentication_incomplete`, e membership não autoriza conteúdo. `POST /api/v1/workspaces` valida origem/CSRF, exige MFA com menos de 5 minutos, aplica a policy de criação e torna o ator owner. `PUT/DELETE /api/v1/workspaces/{workspaceID}/members/{userID}` exige CSRF/Origin e MFA recente; owners gerem roles, administradores delegam apenas `member`, e o último owner ativo é protegido. Rotas de repositório aceitam somente owner/administrador para criar/listar/renomear metadados/grants, reservam mudança de visibilidade ao owner, e a policy global é restrita ao administrador da instalação. Grants exigem membership ativa; admins delegam só `reader`/`publisher`, owners qualquer papel, remoção de membership revoga grants e readmissão não os restaura. Visibilidade pública requer confirmação, mas nenhuma rota serve conteúdo público ou bytes privados. O SHA-256 dos identificadores de rate limit não protege contra adivinhação offline de username/IP em dump do banco.
- Passkeys continuam obrigatórias para v1; uma passkey só satisfaz a política MFA quando o autenticador comprova user verification, não apenas presença/toque.
- A autenticação TOTP local agora pode ser completada ponta a ponta por esses endpoints, mas não há UI, passkeys, reset/recuperação operacional, autorização HTTP, middleware de conteúdo ou rotas administrativas. Não anunciar a fundação como produto utilizável nem como v1.

## Referências

- [Plano — autenticação humana e cadastro](../development-plan.md#8-autenticação-humana-e-cadastro)
- [ADR 0002 — URLs públicas e fronteiras de origem](0002-public-url-and-origin-boundaries.md)
- [ADR 0004 — identidade OIDC e SCIM](0004-authentication-and-scim-identity.md)
- [ADR 0009 — bootstrap local e credenciais](0009-local-bootstrap-and-credentials.md)
- [ADR 0010 — chave mestra local e envelopes](0010-local-master-key-and-secret-envelopes.md)
- [Modelo de ameaças inicial](../threat-model.md)
