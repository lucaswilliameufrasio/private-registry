# ADR 0016 — Publicação de coleções de artefatos genéricos

- **Status:** Aceito para a primeira integração do catálogo e download privado via asset-origin; quotas completas, adapters e recuperação seguem pendentes
- **Data:** 2026-10-22

## Contexto

Artefatos genéricos são coleções versionadas de arquivos prontos, sem semântica SemVer obrigatória. Upload e publicação precisam ser distintos: objetos já recebidos não podem aparecer em busca ou download até o publicador concluir o commit autorizado.

## Decisões

- A identidade de uma versão é `(repository_id, collection_name, version_label)`. O `version_label` é opaco e não recebe validação SemVer; depois de publicada, a identidade e os bytes não podem ser sobrescritos.
- Cada upload session reserva um path relativo dentro da versão, tamanho, MIME e SHA-256 esperados. Paths são portáveis ASCII, sem traversal, caminhos absolutos, separadores alternativos, nomes reservados de Windows ou colisões apenas por diferença entre maiúsculas/minúsculas.
- O conteúdo entra em storage antes da transação de catálogo. Upload sessions retêm a referência ao objeto; uma falha SQL pode deixar objeto órfão, mas não torna conteúdo publicável. Reconciliação futura usa período de retenção antes de GC.
- Publicação exige ao menos um arquivo e nenhuma sessão de upload ativa/incompleta. Em uma transação curta, o serviço revalida o grant `publisher`, grava os arquivos do manifesto, muda a versão para `published` e registra auditoria. O lock de coordenação compartilhado serializa isso com revogações de grants.
- O limite máximo representável para um arquivo nesta migration é 1 GiB; a admissão efetiva é configurada separadamente e limitada ao valor declarado na sessão. Limite agregado de workspace/repositório, reserva de quota e justiça entre tenants continuam necessários antes de declarar a fatia pronta para produção.
- Cada versão admite até 10.000 paths ativos ou recebidos. A criação da sessão conta reservas `receiving`, `uploading` e `uploaded` na transação de autorização, sob o lock compartilhado de escrita; sessões expiradas ou rejeitadas não ocupam vaga. O limite impede receber arquivos que não poderiam ser publicados, mas não é quota de bytes nem substitui limpeza periódica.
- `reader` é explícito; owner, administrador de instalação e membership não recebem leitura implícita. A autorização é checada antes de consultar metadados sensíveis e antes de abrir bytes.
- O serviço de catálogo não serve HTML, JavaScript, SVG ou documentos executáveis pela origem administrativa. Download HTTP requer origem de assets distinta, sem cookies host-only, e uma capability temporária emitida após autorização atual.

## Alternativas rejeitadas

- **Publicar arquivo ao concluir cada PUT:** impediria manifest multi-arquivo atômico e deixaria coleção parcialmente visível.
- **Validar SemVer no formato genérico:** imporia semântica de biblioteca a bundles e assets.
- **Usar path enviado como caminho físico:** mistura namespace lógico e layout de storage e amplia risco de traversal.
- **Servir assets na origem administrativa ou confiar em membership:** contraria os ADRs 0002 e 0014.

## Consequências e trabalho restante

- Migrations v9/v10 criam versões, sessões, arquivos do catálogo e hashes de capabilities de download para SQLite/PostgreSQL. A API recebe cada arquivo em streaming; versões não publicadas ficam fora das consultas de leitores. Download HTTP requer `REGISTRY_ASSET_ORIGIN` distinto, exige autorização atual ao emitir ticket e usa default de 5 minutos (limite de 15).
- A janela de sessão inicial é 24 horas. O claim transacional `receiving → uploading` impede duas leituras concorrentes do mesmo body; falha de storage/DB restaura a sessão para retry e expiração lazy em Receive/StartUpload/Publish libera claims abandonadas. Ainda não existe job periódico de limpeza nem reconciliação/GC de objetos órfãos.
- A operação interna `ExpireUploadBatch` processa até 256 sessões expiradas por chamada, de forma idempotente e sem apagar objetos. Um corte conservador de um segundo evita expiração antecipada por comparação textual de timestamps RFC3339Nano; atualizações condicionais preservam estados já alterados. Ela ainda não está conectada a worker nem constitui a fila persistente de jobs do plano.
- Antes do aceite produtivo ainda são necessários: quota agregada e reserva atômica, limites persistentes por workspace, idempotency keys, recuperação de resultado incerto, job periódico de expiração/limpeza, logs/métricas de downloads, suporte S3 e validação/reconciliação de objetos.

## Referências

- [Plano — invariantes de conteúdo e publicação](../development-plan.md#5-modelagem-e-invariantes)
- [Plano — fluxo de publicação](../development-plan.md#6-fluxo-de-publicação)
- [Plano — artefatos genéricos e assets](../development-plan.md#77-artefatos-genéricos-e-assets)
- [ADR 0002 — fronteiras de origem](0002-public-url-and-origin-boundaries.md)
- [ADR 0014 — grants de repositório](0014-repository-grants.md)
- [ADR 0015 — storage filesystem](0015-content-addressed-filesystem-storage.md)
