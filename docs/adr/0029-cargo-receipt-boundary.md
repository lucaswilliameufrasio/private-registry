# ADR 0029 — Recepção experimental de archive Cargo

- **Status:** Implementação experimental isolada; nenhuma publicação ou serving Cargo disponível
- **Data:** 2026-11-08

## Jornada e invariantes

Após autenticar o publisher e registrar uma reserva, o servidor precisa receber bytes limitados, validar o pacote e guardar um recibo sem confundi-lo com publicação. O cliente nativo envia envelope e archive na mesma requisição; quem integra o endpoint deve autenticar antes de ler o corpo e manter staging privado e imutável, com limites de concorrência, tempo e espaço.

- Uma claim durável exclusiva impede uploads concorrentes. Antes de receber, verificar a credencial, grant exato, identidade, tamanho, digest e metadados vinculados à reserva. Staging e leitura têm limites; falhas não tornam conteúdo visível.
- Validar estrutura e manifesto com as primitivas Cargo, gravar o objeto imutável, reabri-lo e conferir tamanho e digest. A transação de recibo revalida a credencial e o grant, confere claim e política de revisão e registra auditoria. Um objeto gravado antes de falha SQL pode ficar órfão; GC seguro é trabalho separado.
- Recibos verificados precisam ser contabilizados na quota e protegidos no inventário de backup. Enquanto backup Cargo não for completo, recovery parcial deve recusar snapshots que contenham versões ou recibos Cargo verificados; claims incompletas restauradas devem ser invalidadas.
- O estado `uploaded` não é publicação. Revisão humana, autorização atual, quota, unicidade, serving autenticado e o comportamento correto do cliente nativo continuam obrigatórios. Um contexto cancelado não interrompe necessariamente um reader que não coopera; o endpoint deve impor limites de transporte.

## Limites

No worktree isolado, a recepção valida claim, archive e manifesto, confirma digest após readback e grava um recibo auditado sem publicar. Testes locais SQLite/PostgreSQL cobrem limites de concorrência, autorização antes da leitura, revogação durante readback, corrupção, expiração, retenção da revisão e upgrade com reservas anteriores; SQLite também exercita rollback de auditoria e recusa de recovery parcial para recibos verificados. Esses testes não comprovam publicação ou recuperação integral. Ainda faltam verificação integral após integração, revisão humana com grants e decisões, publicação, serving autenticado, backup completo e teste do adapter com Cargo real. A criação de repositórios Cargo e seu adapter continuam indisponíveis.
