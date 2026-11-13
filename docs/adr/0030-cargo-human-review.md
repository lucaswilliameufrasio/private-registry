# ADR 0030 — Revisão humana experimental de Cargo

- **Status:** Em implementação isolada; sem publicação Cargo
- **Data:** 2026-11-08

## Jornada e invariantes

Um owner concede capacidade explícita de revisão a um membro ativo. A capacidade não concede leitura geral ou publicação. Um reviewer diferente do publisher inspeciona um recibo Cargo verificado que está sob revisão e registra aprovação ou rejeição auditada. O acesso e a decisão exigem a capacidade atual no repositório correto; membership, ownership e grant de leitura não substituem essa capacidade.

- Uma aprovação deve vincular o ID exato dos grants de reviewer e publisher, a revisão da política e a identidade do recibo. Revogação ou nova concessão não revive aprovação antiga. A operação futura de publicação revalida tudo na mesma transação coordenada, incluindo usuário, membership e repositório ativos.
- Decisões e suas justificativas são imutáveis. A rejeição não elimina o objeto verificado, não concede autorização e não pode ser confundida com publicação; retenção e descarte seguro seguem pendentes de política de GC. Autoaprovação é proibida.
- As operações humanas HTTP exigem sessão, MFA recente e CSRF. Enquanto sua gestão e o ciclo de publicação não estiverem completos, não disponibilizar esses endpoints nem criar repositórios Cargo por API.

## Limites

A implementação isolada inclui grants e decisões imutáveis com sequência transacional, mas não expõe revisão nem publica conteúdo. Testes focalizados SQLite/PostgreSQL exercitam grant explícito, autoaprovação, retries concorrentes, revogação e nova concessão de reviewer e publisher, mudança de política e rejeição terminal; SQLite também exercita rollback quando a auditoria falha. Esses testes não são gate integral nem prova de suporte. Ainda faltam gestão HTTP com MFA/CSRF, inspeção autorizada do recibo, publicação transacional, serving, recovery integral e exercício com cliente Cargo real sobre o adapter.

Uma extensão separada prepara rotas HTTP condicionais para política, grants, listagem, download e decisão; elas não são conectadas ao servidor por padrão. Testes focalizados do router exercitam MFA, CSRF, revisão e download de dados sintéticos, enquanto a recepção de `.crate` real é verificada separadamente. Listagem e abertura de archive exigem grant atual, excluem rejeições e invalidações e não autorizam publicação. Uma revogação não recolhe bytes já entregues de uma transferência em andamento. Ainda faltam gate integral integrado, avaliação de limites de transporte e teste da jornada completa sobre o adapter real.
