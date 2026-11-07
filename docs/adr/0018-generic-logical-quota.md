# ADR 0018 — Reserva de quota lógica para uploads genéricos

- **Status:** Fundação parcial; gestão administrativa e demais formatos pendentes
- **Data:** 2026-11-07

## Contexto

O plano exige quota lógica por workspace e repositório, com reserva antes do upload e sem contar deduplicação física como economia lógica. Os limites de arquivo e concorrência do processo não fornecem essa garantia. A instalação atual suporta uma instância ativa e já serializa operações de autorização e publicação por uma linha de coordenação SQL.

## Decisão

- A primeira etapa aplica tetos opcionais em bytes no workspace e no repositório aos artefatos genéricos. Ausência de teto representa configuração ainda não definida, não uma promessa de quota ativa. A gestão inicial fica restrita ao administrador ativo da instalação, com MFA recente nas mutações HTTP, auditoria e revisão otimista por recurso. A atualização do limite afeta novas reservas, sem invalidar sessões já aceitas ou apagar dados; o administrador não recebe acesso implícito a conteúdo.
- A sessão reserva o tamanho declarado na mesma transação e sob o mesmo lock que verifica a autorização. Cada sessão em `receiving`, `uploading`, `uploaded` ou `published` conta seus bytes esperados, mesmo quando o objeto é deduplicado. Sessões `expired` ou `rejected` não contam; arquivos publicados não são contados novamente pela tabela de manifesto.
- O worker e a expiração lazy liberam reservas ao marcar sessões expiradas. Sessões expiradas ainda não processadas podem temporariamente bloquear um upload: falhar fechado é preferível a ultrapassar o teto. Não se remove conteúdo por redução de teto; uma operação de tamanho zero não amplia uso já excedido.
- Na publicação futura de outros formatos ou exclusão recuperável, preservar uma contabilização comum e transferência de reserva atômica: esta consulta a sessões genéricas **não** cobre OCI, formatos adicionais ou política de retenção ainda não implementada. Não anunciar quota global completa da instalação.
- As rotas administrativas `GET`/`PUT /api/v1/admin/workspaces/{workspaceID}/generic-logical-quota` e `.../repositories/{repositoryID}/generic-logical-quota` expõem somente a policy. Escritas exigem `expected_revision` e `mode` (`limited` com `limit_bytes` inteiro não negativo; `unlimited` sem `limit_bytes`). Respostas omitem `limit_bytes` quando não há limite. Um conflito de revisão retorna `409`; uma mudança efetiva gera auditoria na mesma transação. Essa interface não expõe uso nem nomes de pacotes.
- `GET /api/v1/admin/workspaces/{workspaceID}/generic-logical-usage` é exclusivo para administrador ativo da instalação e retorna apenas bytes reservados (sessões recebendo ou recebidas ainda não publicadas) e bytes publicados, agregados no workspace, sem nomes de repositórios ou pacotes. Expirados e rejeitados não são contados. Os valores são lógicos, não representam bytes físicos, tráfego nem outros formatos.

## Alternativas e limites

- Contar bytes físicos subestimaria consumo lógico de versões deduplicadas e criaria efeitos entre referências.
- Conferir quota sem transação compartilhada permitiria dois uploads excederem o teto por concorrência.
- Excluir automaticamente dados quando o teto diminui contradiz a política do plano.
- O lock global privilegia correção sobre paralelismo; as consultas e seu custo sob carga precisam de benchmark e eventual evolução coordenada. A quota de instalação, ajustes delegados ao workspace, detalhamento autorizado de uso e a reconciliação permanecem trabalho obrigatório. Revisão otimista detecta escrita obsoleta, mas não substitui idempotência para resposta perdida: o cliente deve reler a policy antes de decidir como proceder.
