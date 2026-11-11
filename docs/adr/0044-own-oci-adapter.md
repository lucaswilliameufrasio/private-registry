# ADR 0044 — Adapter OCI próprio com commit transacional

- **Status:** Experimental, opt-in (`REGISTRY_EXPERIMENTAL_OCI=true`); comprovado com ORAS, sem Docker/containerd, sem recovery
- **Data:** 2026-11-11
- **Substitui a direção de:** [ADR 0005](0005-oci-engine-selection.md) (Distribution atrás de gateway permanece não adotado)

## Contexto

Os spikes 0.5–0.12 mostraram que um motor OCI externo atrás de gateway não ordena o commit remoto em relação à revogação de permissão: o motor pode concluir um push depois de a revogação ser reconhecida. O ADR 0005 deixou como alternativa um adapter próprio que movesse commit, tag e visibilidade para uma transação local.

## Decisão

Implementar o protocolo OCI Distribution dentro do registry (`internal/oci`, rotas `/v2/`), sem processo externo:

- **Blobs** vão para o object store compartilhado (filesystem ou S3), endereçados por workspace + SHA-256. A pertença de um blob a um repositório é uma linha em `registry_oci_blobs`; conhecer o digest de outro repositório ou workspace não dá leitura nem permite referenciá-lo em manifest.
- **Manifests** (≤ 4 MiB) ficam no banco, com suas arestas em `registry_oci_manifest_references`; **tags** em `registry_oci_tags`, por `(repositório, nome da imagem, tag)`.
- **Todo commit** (registro de blob, manifest, movimento de tag, auditoria) acontece dentro de `WithOCIWriteTokenTransaction`, a mesma transação que revalida token, usuário ativo, membership e grant `publisher` sob o lock de coordenação de autorização. Uma revogação reconhecida antes do commit faz o commit falhar; não existe janela em que um motor externo conclua sozinho. Isso atende à condição 1–2 do ADR 0005 por construção, para uma instância ativa.
- **Uploads** são sessões em memória com arquivo em `<data>/oci-staging`, exclusivas do usuário e repositório que as abriram. O digest declarado é verificado sobre todos os bytes antes de qualquer gravação no object store. Sessões não sobrevivem a restart (o staging é esvaziado na inicialização e o cliente reenvia o blob); expiram após 1 h ociosas.
- **Nome do repositório para o cliente:** `<host>/<workspace-id>/<repository-id>/<imagem>`, com a imagem podendo ter vários segmentos.
- **Autenticação:** o token do registry como senha de Basic (o que `docker login`/`oras login` enviam; o usuário é ignorado) ou como Bearer. Token de escrita OCI (`prow_…`, emitido em `POST /api/v1/workspaces/{w}/repositories/{r}/oci-write-tokens` com MFA recente) autoriza push; ele só lê conteúdo se o dono tiver também grant `reader` — sem ele, apenas `HEAD` de blob e progresso de upload, que o push exige. Token pessoal de leitura autoriza pull.
- **Formato `oci`** entra no CHECK de `registry_repositories` (migration v41, rebuild dedicado no SQLite) e as tabelas na v42.
- Repositórios de formatos opt-in (`cargo`, `npm`, `pub`, `oci`) agora podem ser criados pela API **somente** quando o adapter correspondente está habilitado no processo.

## Limites conhecidos

- **Sem revisão humana, quota lógica, reserva de identidade ou imutabilidade de tag** para OCI: tags são mutáveis; digests são imutáveis. O plano da v1 exige esses controles; esta entrega não os cumpre.
- **Sem exclusão e sem GC:** `DELETE` responde 405; blobs não referenciados e objetos de uploads cujo commit falhou ficam órfãos no object store.
- **Sem backup/recovery:** nenhum conjunto de recuperação captura blobs OCI; toda preparação de recovery recusa uma instalação que tenha conteúdo OCI.
- **Sem mount entre repositórios** (o cliente recebe uma sessão de upload comum) e **sem API de referrers** (404; clientes usam o esquema de tag de fallback). `_catalog` não existe.
- **Tamanho de blob** limitado por `REGISTRY_MAX_UPLOAD_BYTES` (teto 1 GiB); layers maiores são recusadas. O staging pode ocupar até `sessões × limite` (sessões = 4 × `REGISTRY_MAX_CONCURRENT_UPLOADS`, máximo 64).
- `/v2/` sem repositório não consegue validar o token (tokens são por repositório): `docker login` "funciona" com qualquer senha e a recusa aparece no primeiro push/pull.
- A autorização de leitura é verificada no início da requisição; uma revogação durante um download em andamento não o interrompe.
- Uma instância ativa. Sessões de upload em memória não funcionam com várias instâncias.

## Evidência

- `internal/oci`: publicação, leitura, índice multi-plataforma, capacidade, isolamento entre repositórios e revogação entre upload e commit, em SQLite e PostgreSQL real; três repetições com race.
- `internal/server`: jornada HTTP (upload em chunks e monolítico, chunk fora de ordem, digest divergente, manifest com layer ausente/estrangeira, media type, tags e paginação, tokens trocados entre repositórios, revogação durante push, publisher sem reader, rotas e criação de repositório ausentes sem opt-in); três repetições com race.
- `cmd/registry`: `serve` real atrás de TLS local com **ORAS 1.3.4**: push recusado com token de leitura e com token desconhecido, push, pull com conferência de bytes, listagem de tags, retag e pull anônimo recusado; três repetições com race.

Existe uma jornada com Docker CLI + daemon (`TestExperimentalOCIServeDockerJourney`: `docker import`, login, push recusado com token de leitura, push, `rmi`, pull e conferência do conteúdo), mas ela só roda com `OCI_TEST_DOCKER=1` e **não passou neste ambiente**: o daemon rootless não alcança o loopback do host (`connection refused` em `/v2/`), então o resultado diz respeito à fixture, não ao adapter. Ela precisa ser executada com um daemon que alcance o registry e confie no certificado.

Não comprovado: Docker, containerd, Podman, Buildx ou imagens reais multi-arquitetura por cliente; layers grandes; S3 real; crash no meio de upload ou commit; concorrência de push da mesma tag.
