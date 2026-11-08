# ADR 0027 — Credencial de escrita Cargo experimental

- **Status:** Implementação experimental isolada; sem adapter Cargo produtivo
- **Data:** 2026-11-08

## Objetivo e fronteiras

O cliente Cargo nativo precisa de uma credencial de publicação distinta do token pessoal de leitura. A credencial pertence a uma pessoa, a um único repositório Cargo e ao grant explícito de publisher que a autorizou. Membership isolada não concede publicação; revogar o grant invalida a credencial mesmo se outro grant for criado depois. A emissão deverá exigir sessão humana com MFA recente e proteção CSRF na fronteira HTTP, e o segredo deverá ser revelado apenas uma vez.

## Invariantes a implementar

- Persistir apenas verificador do segredo aleatório, com expiração limitada, revogação auditada e vínculo ao ID exato do grant. Validar usuário, membership, repositório, formato, expiração, revogação e grant atual sob o mesmo lock transacional que protege alterações de grants.
- Uma publicação futura deverá validar a credencial na mesma transação coordenada que reserva ou confirma a mudança; validar uma vez e reutilizar a identidade depois não impede corrida com revogação. A credencial de leitura não deve autorizar escrita nem vice-versa.
- A restauração isolada deve invalidar credenciais de escrita junto com sessões e demais capacidades antes de qualquer promoção; não habilitar o novo schema de credenciais sem atualizar e testar esse procedimento.
- Falhas de emissão e respostas perdidas não devem expor o segredo em logs ou criar sucesso fictício; listagem nunca devolve segredo ou verificador. O desenho de rotação, reconciliação e limites de emissão precisa ser verificado antes de expor o endpoint.

## Evidência e pendências

Uma implementação isolada adiciona schema de credencial, emissão, listagem de metadados, revogação auditada, validação transacional e invalidação no recovery parcial. Rotas experimentais de gestão seguem a sessão humana, MFA recente e CSRF existentes; a emissão retorna o segredo uma única vez, e a listagem não o retorna. Testes locais SQLite/PostgreSQL exercitam grants, regrant, suspensão, membership, expiração, separação de tokens, rollback e serialização de revogação; um teste SQLite verifica invalidação no destino recuperado preservando a origem e testes HTTP exercitam MFA, CSRF, grant e `no-store`. Isso não é suporte produtivo. Ainda faltam revisão e gate integral após integração, limites operacionais de emissão, integração com publicação e clientes reais. Enquanto isso a criação de repositórios Cargo e o adapter permanecem indisponíveis na API.
