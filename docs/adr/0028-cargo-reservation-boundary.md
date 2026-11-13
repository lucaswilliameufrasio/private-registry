# ADR 0028 — Reserva durável experimental Cargo

- **Status:** Implementação experimental isolada; nenhuma rota de publicação disponível
- **Data:** 2026-11-08

## Jornada e invariantes

Uma pessoa autorizada publica um pacote Cargo em um repositório específico. O cliente nativo envia um envelope e archive em uma única requisição; o servidor deve autenticar antes de consumir o corpo e limitar concorrência, tempo, tamanho e staging. A validação do envelope e archive não constitui publicação. Para preservar identidade e quota diante de concorrência ou perda de resposta, o servidor precisa registrar uma reserva durável antes de gravar ou disponibilizar o objeto.

- A reserva vincula workspace, repositório Cargo, nome e versão canônicos, tamanho, digest, metadados validados, publisher, credencial e grant. O servidor deriva as chaves e revalida autoridade na transação coordenada; reenvio idêntico pelo mesmo ator pode reconciliar a reserva, mas outro conteúdo ou ator não pode assumir sua identidade.
- Quota deve contabilizar reservas e versões Cargo em conjunto com formatos genérico e Go, no workspace e no repositório, sem contagem dupla na transição para publicado. A quota é verificada novamente ao confirmar publicação; falha não pode gerar sucesso nem objeto servido.
- Revisão exigida retém a publicação, não retorna sucesso fictício ao cliente nativo, e decisões dependem de reviewer distinto, grant de publisher específico e revisão da política. O lifecycle deve permitir reconciliação após falha sem reviver credenciais ou grants revogados.
- Recovery isolado deve invalidar reservas e claims, reter referências a objetos verificados e recusar promoção ou restore parcial enquanto inventário Cargo não for recuperável. Expiração, concorrência, auditoria e coleta de objetos sem referência precisam de testes; nenhuma rotina pode apagar conteúdo compartilhado por conveniência.

## Limites

No worktree isolado, uma reserva transacional deriva identidades, revalida a credencial sob o lock de grants, limita quota cruzada com Go e genéricos, reconcilia retry idêntico da mesma credencial e audita criação/cancelamento. Um worker durável expira lotes sem excluir objetos; o recovery expira e invalida reservas na cópia. Testes SQLite/PostgreSQL cobrem concorrência, quota cruzada, audit rollback, worker e recovery parcial. Isso não autoriza nem publica conteúdo. Antes de expor rotas, concluir staging limitado, recepção, revisão, confirmação, serving autenticado e recovery completo, validar o conjunto integrado e executar o gate integral. O teste com Cargo real deve exercitar publicação, consumo, yank e lockfile sobre o adapter, não apenas sobre uma fixture de protocolo.
