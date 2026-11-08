# ADR 0040 — Dist-tags npm e leitura experimental

- **Status:** Em implementação isolada; sem rotas públicas
- **Data:** 2026-11-08

## Fronteira

A leitura de tarball exige token pessoal de leitura vinculado ao grant original, resolução da versão publicada no mesmo repositório e autorização anterior ao acesso ao storage. Revogação não recolhe bytes já entregues. O envelope de resposta e as URLs do packument ainda precisam de validação com cliente real; esta primitiva isolada não habilita npm.

Mover dist-tags é operação distinta da publicação: exige capacidade explícita, auditável e revogável, não concedida por membership nem pela credencial de publicação. Uma tag só pode apontar para versão publicada do mesmo pacote e repositório. Alterações concorrentes devem ser condicionais à revisão conhecida, e a movimentação deve ser atômica com seu histórico e auditoria. Rotas humanas exigem sessão, MFA recente e CSRF; interoperabilidade de publicação npm e tratamento de tags solicitadas pelo cliente permanecem pendentes, sem sucesso fictício.

O protocolo npm nativo não envia revisão de tag: uma publicação nova expressa a intenção de mover as tags informadas e, com o grant separado ativo, as atualiza sob o mesmo lock e transação da versão, em ordem de commit. Um retry de versão já publicada não move tags que tenham avançado; retorna conflito. Alterações humanas independentes continuam exigindo revisão explícita.

## Evidência parcial

Testes focalizados três vezes com race em SQLite, PostgreSQL e Floci exercitaram leitura de tarball e metadados após publicação, isolamento por repositório, revogação e regrant do leitor, e exclusão de reserva pendente. Tags foram testadas para grant separado, alvo publicado, concorrência, revisão, revogação e histórico imutável; em SQLite falha de auditoria reverteu a criação. A migration v32 passou em upgrade e rollback injetado nos dois bancos, três vezes com race. Estes testes não verificam rotas, URLs, comandos npm reais, exclusão de tags ou backup/restauração completo; a API segue fechada.
