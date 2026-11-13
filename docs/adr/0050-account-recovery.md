# ADR 0050 — Recuperação de conta

- **Status:** Implementado; envio por e-mail no [ADR 0054](0054-transactional-email.md)
- **Data:** 2026-11-12

## Contexto

Não existia reset de senha. Quem esquecesse a senha, ou perdesse o TOTP e os códigos de recuperação, ficava sem acesso; se fosse o único administrador, a instalação inteira ficava sem dono. O proprietário decidiu: códigos de recuperação primeiro; sem eles, reset administrativo explícito e auditado que não entrega sessão; procedimento local para o último administrador; contas federadas recuperam o login no provedor.

## Decisão

- **Link de recuperação:** um administrador da instância (CSRF e MFA recente) chama `POST /api/v1/admin/users/{id}/recovery` com `reset_mfa`. Recebe um token `prrst_…` de uso único, válido por 24 h, mostrado uma vez e entregue por um canal dele. Um link novo invalida os anteriores. Não vale para a própria conta, para contas de serviço nem para contas suspensas. Para contas sem senha local (Muira) só há reset de MFA.
- **Uso:** `POST /api/v1/auth/recovery` com o token e, para contas com senha local, a nova senha (mesmas regras do bootstrap). Define a senha, remove TOTP, códigos de recuperação e passkeys quando `reset_mfa`, e revoga todas as sessões da conta. Não abre sessão: a pessoa entra normalmente e, se os fatores foram removidos, cadastra um novo (administradores são obrigados a isso).
- **`registry recover-admin`:** no servidor, em terminal interativo, pede o login de um administrador existente e uma nova senha; define a senha, remove os fatores, revoga as sessões e audita como operador local. Não promove ninguém e não cria contas.
- A recuperação isolada a partir de backup revoga links pendentes, como faz com tokens.

## Limites

Sem e-mail configurado, nem o link nem um aviso são enviados à pessoa. Com e-mail ([ADR 0054](0054-transactional-email.md)), o administrador pode enviar o link ao e-mail confirmado, e a própria pessoa pode pedir um link que só redefine a senha.

## Evidência

HTTP em SQLite (autorrecuperação e não administrador recusados, link substituído pelo novo, senha fraca recusada, senha nova valendo e antiga não, sessão anterior revogada, TOTP e passkey removidos, conta federada só com reset de MFA, `RecoverAdministrator` com login desconhecido e não administrador recusados, administrador recuperado indo para o cadastro de TOTP, auditoria) e PostgreSQL. Três repetições com race.
