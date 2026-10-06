# Spike 0.10 — receipt OCI, reconciliação e alcance persistido

**Data:** 06/10/2026

**Estado:** prova limitada com SQLite/Distribution/ORAS reais. Não é coordenador de produção nem solução para a corrida de commit remoto do spike 0.9.

## Reprodução

```sh
GOMAXPROCS=4 make setup-oci
GOMAXPROCS=4 go test -tags=integration -count=3 -run '^TestOCIDurableRelease' -v ./internal/spikes/ociprobe
GOMAXPROCS=4 make verify
```

Mesmos tools fixados, filesystem OCI sintético, Unix socket privado e gateway loopback. SQLite em arquivo próprio, WAL/FULL/foreign keys; sem banco in-memory ou storage mock. Floci permanece S3 de desenvolvimento, sem participação nesta prova local OCI.

## O que foi exercitado

Um conjunto pequeno de tabelas de fixture persiste tentativa (`prepared`, `verified`, `published`, `rejected`), digest esperado, rotas candidatas e rotas distribuíveis qualificadas pelo repositório. O estado de permissão atual também está no SQLite, não em flag/mapa de processo. Dados/gráficos OCI são reais, com índice amd64/arm64 e seis blobs do spike 0.6.

O envio interno direto ao motor prepara conteúdo, **não** anuncia sucesso de publicação nativa ao consumidor. O gateway de consumo só permite GET/HEAD cujo path está em rotas distribuíveis de tentativa publicada; sem estado disponível, retorna 503 e não faz bypass para o motor. Não é apenas projeção da UI.

Provas:

- Publicação baseline liberada continua disponível enquanto outro repositório fica pendente/rejeitado, mesmo com digests idênticos. Aprovação de digest não é alcance global.
- Motor contém tag e layer pendentes (GET direto 200); gateway mantém GET/HEAD de tag, manifest por digest e layer em **404**.
- Permissão de publicação revogada **antes da transação de liberação** nega a tentativa verificada. Não desliga downloads anteriores por revogar o publicador.
- Uma tentativa perde o registro de receipt após o envio remoto, permanecendo `prepared`. Fechar/reabrir SQLite e reiniciar o gateway não a promove nem remove a rejeição anterior.
- Restabelecer permissão não revive tentativa rejeitada; tentativa não reconciliada também não é liberada.
- Reconciliação resolve tag no motor, compara digest ao preparado e exporta por digest imutável via ORAS; verifica o grafo completo por SHA-256/tamanho antes de gravar `verified`. Digest inesperado é negado.
- Transação de liberação muda fase e insere todas as rotas em conjunto, condicionada ao estado atual de permissão. Cancelamento antes da operação não publica.
- Trigger real provoca erro na **segunda** inserção de rota, após UPDATE da fase e primeira inserção: rollback deixa fase `verified` e **zero rotas distribuíveis** da tentativa.
- Depois da liberação válida, ORAS exporta o grafo pelo gateway e os seis blobs têm os digests esperados; liberação duplicada é negada.
- Fechar o banco com gateway ativo produz **503**, não fallback ao motor. Reabrir banco/reiniciar gateway preserva publicações já liberadas.

O teste falhou ao remover a condição SQL de permissão atual: `remote commit ignored current revocation`. A condição foi restaurada antes da verificação completa.

## Fronteira provada e fronteira NÃO provada

Motor pode conter resultado de uma operação sem que o gateway o torne distribuível. Persistir e reconciliar essa separação evita promoção silenciosa após interrupção nessa fixture. Não desfaz o commit no motor, não implementa remoção segura nem permite ignorar quotas/pins/GC de material pendente.

Não altera a fonte de verdade dos dados OCI: manifests/blobs continuam no motor. O experimento avalia estado de elegibilidade/alcance no gateway, não substitui esses dados por um catálogo fictício. A eventual composição de produção e seu ADR continuam abertos.

Aqui a revogação é reconhecida antes de iniciar a transação SQL de liberação. Não foi testada revogação concorrente durante essa transação ou durante requisição de download. Não oferece retroativamente atomicidade entre SQL e commit remoto, nem fixa sem decisão o instante de acknowledgment da revogação. A [corrida do spike 0.9](oci-commit-revocation.md) permanece reproduzida/não resolvida.

## Limites ainda obrigatórios

- Só arquivo SQLite, pool com uma conexão e tabelas de fixture. Sem implementação de schema/repositorios produtivos, JWT/RBAC/reviewers/auditoria, delegação ou port PostgreSQL do coordenador.
- Reabertura controlada de banco/gateway, **não** SIGKILL/power-loss, processo de recovery independente ou multi-host.
- Rejeição é marcada explicitamente pelo teste após negar liberação; não existe workflow/worker completo de rejeição, retry e recuperação.
- Rotas candidatas são derivadas do layout sintético confiável. Gate não é parser/roteador OCI geral e não cobre catálogo/tags list, aliases, ranges, mounts ou referrers. Repositórios de tentativa são exclusivos; não há atualização concorrente das tags durante reconciliação/liberação.
- Ainda validar coordenação de conteúdo/tag imutável, revisão/checks atuais, resultado remoto incerto, quotas, leases/pins duráveis, backup/GC/recovery e comportamento de todos os clientes reais antes de adotar o motor.
- Sem retorno 201/202 fictício para envio nativo pendente, sem liberar material apenas pela existência de tag/receipt, sem esquecer conteúdo remoto rejeitado como se não consumisse armazenamento.

Esta fatia não conclui fase 0, aceite OCI ou decisão arquitetural definitiva.

## Verificação

`GOPROXY=off GOSUMDB=off GOMAXPROCS=4 make verify` completo passou: build sem CGO, formatação, vet normal/integration, sintaxe Bash, testes sem cache, integrações reais três vezes e race detector. Binários/imagens/caches preparados não são prova de instalação offline/egress do produto.

Continuação 0.10 posterior ao commit/push `68c341d`, ainda não commitada.

Na retomada antes do commit, uma execução foi interrompida pelo restart da sessão; outra perdeu o container PostgreSQL (exit 255, `OOMKilled=false`, sem shutdown normal no tail do log). Eventos Docker/journal disponíveis não estabeleceram a causa. Nova execução completa passou, incluindo três repetições/race; nenhum retry SQL ou restart automático da fixture foi introduzido para esconder o incidente. A causa externa/transitória permanece não demonstrada.
