# ADR 0015 — Armazenamento local de conteúdo imutável

- **Status:** Aceito; driver filesystem está integrado ao catálogo genérico e à origem de assets privada; S3, quotas e recuperação completa permanecem pendentes
- **Data:** 2026-10-22

## Contexto

A fase 2 começa pelo conteúdo genérico para validar a fronteira de armazenamento antes dos adapters de protocolo. O plano exige streaming com limite real, digest próprio, objetos imutáveis, autorização antes de ler storage e tratamento explícito da falta de transação distribuída entre banco e armazenamento.

## Decisões

- O primeiro driver é filesystem local, separado do arquivo do banco sob o diretório de dados da instalação. O root do object store é privado; arquivos são criados sem permissão para outros usuários.
- Objetos são endereçados por workspace UUID e SHA-256 em lowercase. Deduplicação fica limitada ao workspace; digest conhecido não concede acesso e nunca substitui grants por repositório.
- Writes são streams limitados por bytes, calculam SHA-256 enquanto copiam para staging no mesmo filesystem e finalizam sem substituir objetos existentes. Uma chave já existente só é aceita depois de verificar seu tamanho e digest.
- Leitura valida o objeto antes de retornar o stream e suporta ranges sem materializar o objeto em memória. A camada de storage não autentica usuários nem decide autorização; o serviço chamador deve revalidar acesso ao repositório antes de abrir objeto.
- Storage e SQL não formam uma transação distribuída. Um objeto completo sem referência no catálogo é órfão, nunca publicável por si só; reconciliação/GC só poderá removê-lo após inventário de referências e período de retenção.
- O driver S3 terá implementação/capacidades explícitas. Floci serve para integração de protocolo, não prova atomicidade de storage S3 real nem substitui o aceite concorrente descrito no ADR 0003.

## Alternativas rejeitadas

- **Usar nomes de arquivo/paths fornecidos pelo cliente no storage:** aumenta superfície de traversal, colisões e dependência do layout físico; nomes lógicos pertencem ao catálogo e não são caminhos locais.
- **Sobrescrever um objeto existente:** viola imutabilidade e pode alterar bytes de versões já publicadas.
- **Deduplicar globalmente por digest:** cria cross-workspace coupling e potenciais side channels de existência/consumo.
- **Servir diretamente de um caminho conhecido sem checar grants:** contorna a fronteira de autorização por request e é proibido pelo ADR 0014.

## Consequências e trabalho restante

- `internal/storage` fornece o driver filesystem e seus limites; o catálogo genérico usa upload sessions, publicação explícita e downloads via capability temporária. Adapters de protocolo e CLI de publicação/consumo ainda não existem.
- Storage ainda precisa de operações paginadas de reconciliação, política de quota/reserva, integração com transações/publicação, S3, recovery, métricas e testes de falha/crash.
- O serviço valida grant `reader` antes da consulta do arquivo e da abertura do objeto; download por ticket revalida ticket ativo/expiração no gateway da origem de assets. Ticket emitido continua válido até expirar mesmo se o grant do emissor for revogado. Cópias baixadas não são recolhidas.
- A decisão deve ser revisada se o filesystem alvo não suportar hard-link atômico no mesmo volume ou se uma implantação exigir outro modelo de durabilidade.

## Referências

- [Plano — invariantes de conteúdo e publicação](../development-plan.md#5-modelagem-e-invariantes)
- [Plano — fluxo de publicação](../development-plan.md#6-fluxo-de-publicação)
- [Plano — armazenamento e quotas](../development-plan.md#13-armazenamento-quotas-e-consistência)
- [ADR 0003 — backup e restore](0003-backup-and-restore-boundaries.md)
- [ADR 0014 — grants de repositório](0014-repository-grants.md)
