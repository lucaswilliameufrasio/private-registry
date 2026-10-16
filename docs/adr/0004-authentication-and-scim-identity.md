# ADR 0004 — Identidade de login e provisionamento SCIM

- **Status:** Contrato de identidade aceito; implementação, saúde/freshness e recuperação permanecem abertas
- **Data:** 2026-10-12

## Contexto

Login OIDC e provisionamento de diretório têm funções distintas: OIDC autentica uma pessoa; SCIM mantém continuamente a conta e grupos, mesmo sem novo login. Identificadores como email e nome podem mudar ou colidir. Remoção de grupo não deve apagar concessões manuais independentes.

O spike 0.18 comprova uma configuração local real de Authentik 2026.8.3 com authorization-code + PKCE, RS256/JWKS e `sub` igual ao SCIM `externalId`, distinto do email. Mudanças incrementais, remoção seletiva de grupo e `active:false` chegaram ao target da fixture. Health de falha, bloqueio de acesso e reconciliação continuam não aceitos.

## Decisão

- Identidade OIDC é única por `(provider_id, issuer, subject)`. Email/nome não é chave de autenticação nem condição suficiente para auto-vincular conta existente.
- Vincular identidade federada a conta local exige sessão recente e confirmação explícita ou um fluxo de provisionamento autorizado que valide a referência estável configurada.
- O registry implementa SCIM 2.0 como target; Authentik é a primeira integração de referência opcional. OIDC autentica, SCIM atualiza estado de conta e grupos.
- Usuário SCIM é correlacionado por identificador estável do provider, validado pelo vínculo configurado; credencial SCIM é exclusiva/restrita à integração, não concede administração global.
- Grants derivados de grupos guardam a origem do mapeamento. Remover usuário de um grupo retira somente grants daquele mapeamento; grants manuais e outros grupos permanecem.
- `active:false` é estado de autorização vinculante: deve bloquear senha, passkeys, sessões, tokens pessoais e demais métodos ligados à conta; revoga sessões/tokens e não libera publicação pendente. Reativar conta não ressuscita sessão/token revogado.
- Conta local de emergência fica fora da gestão SCIM; contas de serviço independentes não são desativadas automaticamente e exigem avaliação/rotação explícita.
- Falha de conectividade nunca é interpretada como remoção de grupo nem permite expansão de acesso.

## Alternativas rejeitadas

- **Auto-link por email verificado ou nome coincidente:** pode unir identidades distintas e contornar ownership; rejeitado.
- **Usar email como `sub` ou `externalId`:** atributo mutável e frequentemente redigível; rejeitado como chave.
- **Apagar todos os grants ao remover um grupo:** destrói concessões manuais e de outras origens; grants precisam de provenance.
- **Usar logout federado como revogação local:** não invalida necessariamente sessões/tokens locais; estado e revogação pertencem ao registry.
- **Desativar conta de serviço porque seu criador perdeu acesso:** credencial é identidade independente; bloquear apenas por regra própria e decisão auditada.

## Gaps e condições de aceite

- O teste usa Authentik → target SCIM sintético, não o futuro endpoint/DB do registry nem autorização real.
- É obrigatório definir e testar sinal confiável de freshness/falha sem usar ausência de eventos como heartbeat; status `info` não prova sync saudável.
- Default de uma hora após falha comprovada deve bloquear só usuários gerenciados afetados, incluindo sessões/tokens/métodos alternativos; conta local de emergência, serviços independentes e conteúdo público continuam disponíveis.
- Reconciliação bem-sucedida remove apenas bloqueios de indisponibilidade, respeita estado ativo/grants/policies atuais e não reativa sessões ou tokens revogados. Exceções temporárias exigem reautenticação, justificativa, expiração e auditoria.
- Full sync Authentik 2026.8.3 terminou `done/info`, mas em um teste não enviou PUT/PATCH para corrigir drift externo sintético. A estratégia de saúde e recuperação ainda não foi escolhida; não adotar essa full sync como reconciliação até prova adicional.
- Testar isolamento de tenants, revogação concurrente com upload/review, egress/TLS, rotação de credencial SCIM e falha de DB/job.

## Referências

- [Plano — identidade e SCIM](../development-plan.md#8-autenticação-humana-e-cadastro)
- [Spike Authentik OIDC/SCIM](../spikes/authentik-oidc-scim.md)
- [Modelo de ameaças inicial](../threat-model.md)
