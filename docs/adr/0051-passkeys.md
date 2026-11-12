# ADR 0051 — Passkeys

- **Status:** Implementado; provado com autenticador de software, não com navegadores reais
- **Data:** 2026-11-12

## Contexto

O plano exige passkeys na v1, e o proprietário decidiu que uma passkey pode substituir senha e segundo fator quando o autenticador comprova a verificação do usuário (PIN ou biometria); presença sem verificação não satisfaz MFA.

## Decisão

- Biblioteca `github.com/go-webauthn/webauthn` v0.18.2. O relying party é a origem canônica do registry; credenciais registradas numa origem só valem nela. Origens por IP não suportam passkeys, que ficam indisponíveis.
- **Cadastro** (`POST /api/v1/auth/passkeys/registration/start` e `/finish`): exige sessão, CSRF e, se a conta já tem um segundo fator, MFA recente. Pede credencial residente (descobrível), verificação do usuário obrigatória e nenhuma attestation. Máximo de 20 por conta. Contas de serviço não têm passkeys.
- **Login sem senha** (`.../login/start` e `/finish`): discoverable, verificação do usuário obrigatória. Abre uma sessão já em nível MFA (conta como segundo fator recente). Cada desafio vale uma vez, mesmo para autenticadores cujo contador fica em zero; um contador que regride é recusado.
- O estado de cada cerimônia viaja num cookie `__Host-` selado com a chave mestra, válido por 5 minutos.
- `GET /api/v1/auth/passkeys` lista; `DELETE .../{id}` remove (MFA recente). O reset de MFA da recuperação de conta também remove passkeys.

## Limites

- Uma conta só com passkey que entrar por senha cai no fluxo de TOTP: a passkey não é usada como segundo fator depois da senha.
- Cadastro obrigatório de fator para administradores continua sendo TOTP; a passkey pode ser adicionada depois.
- Não há verificação de attestation nem lista de autenticadores permitidos.
- Exercitado com um autenticador de software nos testes HTTP e com o autenticador virtual do Chromium pela interface web; Safari, Firefox e chaves físicas não foram testados.

## Evidência

HTTP em SQLite com autenticador de software ES256: cadastro exigindo UV e chave residente, cadastro de outra origem recusado, login sem senha em nível MFA, listagem, recusa sem UV, de outra origem, de asserção repetida e sem o cookie da cerimônia, conta suspensa recusada, passkey removida deixando de funcionar. Três repetições com race.
