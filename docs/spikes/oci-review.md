# Spike 0.7 — revisão OCI, resposta nativa e visibilidade de blobs pendentes

**Data:** 05/10/2026

**Estado:** limites do cliente/motor e mitigação experimental comprovados. Não existe workflow de revisão, fila durável ou gate de produção.

## Reprodução

```sh
GOMAXPROCS=4 make setup-oci
GOMAXPROCS=4 go test -tags=integration -count=1 -run '^TestOCIReviewBlocksNativeSuccessAndPendingBlobDownloads$' -v ./internal/spikes/ociprobe
GOMAXPROCS=4 make verify
```

Usa Distribution 3.1.2 e ORAS 1.3.4 já fixados, filesystem/sockets/dados próprios e gateway HTTP loopback de teste. S3 de desenvolvimento continua Floci. Credenciais/RBAC não são reimplementados neste teste: o motor/gateway de storage é uma fixture pass-through, separada da [prova JWT/revogação](oci-auth.md).

## Resposta nativa: recebimento não é publicação

ORAS envia primeiro os blobs e depois o manifest. O gateway experimental nega o `PUT` do manifest de uma tag que exige aprovação com 403/erro OCI `DENIED`.

Resultado real: **ORAS termina com erro**, mostrando `denied: native publication blocked`; o manifest/tag não existe (GET 404). Não retornar 201/202 de sucesso nativo para fingir publicação pendente. Este probe não salva um recebimento/manifest em fila nem fornece recibo de tentativa; só caracteriza o protocolo. O futuro fluxo com API/CLI administrativa deve distinguir recebimento, aprovação e publicação e explicitar essa limitação de envio nativo.

Prova feita com artefato ORAS, não cliente Docker de imagens. A matriz de clientes reais continua obrigatória antes de anunciar compatibilidade.

## Limite reproduzido: gate só no manifest não oculta blobs

Mesmo sem manifest publicado e após falha nativa, GET do digest do blob recém-enviado retornou **200 e o conteúdo pendente exato**. Token/visibilidade de repositório por si só não garante sigilo do material em revisão. Conhecer o digest não pode conceder acesso a conteúdo ainda não distribuível.

Config/blobs compartilhados que já pertencem a uma publicação válida exigem tratamento por alcance, não bloqueio global do digest: ocultar toda a área do repositório interromperia downloads existentes.

## Mitigação comprovada na fixture

Um mapa de paths de blobs **qualificados por repositório** recebe referências apenas após `PUT` de manifest efetivamente aceito pelo motor (201). Downloads GET/HEAD consultam esse conjunto de conteúdo publicado:

- blob exclusivamente pendente passa a GET/HEAD **404**;
- blob de versão previamente publicada continua GET **200**, bytes intactos;
- aprovação externa sintética, sem permissão atual do publicador, ainda produz erro nativo e manifest ausente;
- após aprovação **e** permissão atual, retry ORAS publica normalmente; manifest e blob ficam acessíveis;
- Locations de uploads são reescritas para o gateway do probe, não para permitir bypass do gate.

O código é exclusivo do teste e deliberadamente limitado a manifests de um artefato/tag conhecidos. Aprovação/permissão são inputs atômicos de fixture, **não** autenticação de reviewer, prevenção de autoaprovação, workflow/API, checks de conteúdo ou auditoria implementados. Nenhum requisito foi marcado como entregue por existir uma flag.

## Contratos ainda obrigatórios

- Estado de publicação/reachability durável, reconciliável com o motor e qualificado por repository/workspace; não confiar em mapa em memória ou evento isolado.
- Coordenar acknowledgment do motor e commit/projeção SQL. A fixture atualiza o mapa após o 201 upstream; não prova atomicidade, restart, atraso/falha de projeção ou exatamente uma liberação.
- Revalidação durante a mesma requisição de commit, tokens/reviewers revogados, checks atuais, sem autoaprovação e ações de liberação separadas/auditadas.
- Quotas de uploads/blobs pendentes, rejeição/liberação de identificador sem reutilizar versão já publicada, cleanup/GC com leases/pins e histórico.
- Mount entre repositórios deve validar origem/destino e nunca contornar visibilidade/revisão. Este probe não implementa mount autorizado nem inventário/referrers global.
- Caminhos/aliases/ranges/redirects, blobs compartilhados, manifests por digest, índices multiplataforma e todos os métodos OCI precisam de gate consistente, não roteamento ad hoc do teste.

Gate apenas no manifest é insuficiente para o aceite OCI acordado. Export/GC e scopes foram demonstrados em outros spikes, mas ainda não há composição completa segura de revisão/auth/reachability/quotas/backup/GC. ADR e aceite do motor permanecem abertos.

## Verificação e falhas de infraestrutura observadas

`GOPROXY=off GOSUMDB=off GOMAXPROCS=4 make verify` completo passou: build sem CGO, formatação, vet normal/integration, sintaxe Bash, testes sem cache, integrações reais três vezes e race detector.

Uma tentativa anterior encontrou colisão de bind do RootlessKit. O helper compartilhado de Floci agora remove o ID exato do container parcialmente criado antes de tentar novamente, no máximo três tentativas e somente para essa assinatura de erro; cleanup com falha e erros distintos não são mascarados. Testes de subprocesso cobrem essas situações, e o teste de retry falhou quando a repetição foi desativada. Integrações continuam usando Floci real.

Outra tentativa falhou com conexão PostgreSQL encerrada por comando administrativo. A falha não reapareceu em três repetições isoladas nem na verificação completa posterior; causa não estabelecida. Fixture passa a capturar estado Docker e tail do log do servidor antes da limpeza em caso de falha, sem retry automático de operações de banco. Não declarar essa falha corrigida apenas porque uma execução posterior passou.

Esta continuação é posterior ao commit/push `a514b6d` dos spikes 0.2–0.6; o spike 0.7 e os ajustes de fixture ainda não estão nesse commit.
