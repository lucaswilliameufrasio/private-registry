# Spike 0.6 — export OCI multiplataforma, recuperação e GC read-only

**Data:** 05/10/2026

**Estado:** grafo de índice amd64/arm64 restaurado com digests preservados e GC conservador comprovados. Aceite completo do motor OCI continua aberto.

## Reprodução e diferença para o trabalho anterior

```sh
GOMAXPROCS=4 make setup-oci
GOMAXPROCS=4 go test -tags=integration -count=1 -run '^TestOCI(Index|Export)' -v ./internal/spikes/ociprobe
GOMAXPROCS=4 make verify
```

Os tools continuam Distribution 3.1.2 e ORAS 1.3.4 fixados no [spike de autenticação](oci-auth.md), sem baixar/selecionar outro backend. S3 de desenvolvimento permanece Floci; esta fatia usa filesystem OCI separado.

Não repete o aceite de autenticação: testa um novo contrato de dados/GC. O gateway desta fixture de storage é pass-through **sem autenticação**, em loopback, e o motor só escuta Unix socket privado em diretório exclusivo. A prova de autorização/revogação é separada; não alegar que já existe composição completa de gateway/políticas/backup/GC.

## Grafo real e export independente do storage interno

O teste cria um OCI Image Layout sintético com imagens linux/amd64 e linux/arm64, uma layer gzip válida compartilhada, configurações por plataforma e índice raiz. ORAS publica esse layout no Distribution real.

Grafo alcançável: **6 blobs distintos** — índice, dois manifests filhos, duas configurações, uma layer compartilhada. O teste resolve o digest do índice no motor e o compara ao original. Não executa a layer nem baixa imagem pública.

`oras cp --to-oci-layout` exporta a raiz e todos os filhos. Verificador próprio de fixture percorre recursivamente descriptors, verifica SHA-256 e tamanho de cada conteúdo, schema/mediaType e orçamento de nós/bytes. Sucesso do comando não substitui essa inspeção. Testes negativos removem um manifest filho ou corrompem a raiz e exigem rejeição do export incompleto.

Isso exporta **uma raiz/tag conhecida**, não um inventário completo de todos os repositórios/tags/referrers. Captura consistente de inventário global e inclusão de publicações pendentes continuam obrigatórias.

## Barreira mutável e GC real

1. Commitar uma layer/blob sintético sem referência de manifest e comprovar HEAD 200.
2. Reiniciar a fixture em `storage.maintenance.readonly.enabled=true`. Nova tentativa de upload recebe **405**, não sucesso falso ou erro genérico interpretado como bloqueio.
3. Exportar grafo completo nesse estado; criptografar tar do layout com age.
4. Executar `registry garbage-collect` real, com o servidor read-only ainda ativo.
5. Sem reiniciar esse servidor depois do GC, confirmar índice resolvível e exportar/verificar novamente todos os seis blobs. Blob órfão passa a HEAD **404**.

Usa GC conservador padrão, **sem `--delete-untagged`**. Não comprova remoção de manifests históricos/sem tag, leases/pins no banco, GC com publicação concorrente ou restart durante job. A mudança para read-only nesta fixture exige reiniciar o processo; não é implementação de barreira online sem interrupção para o produto. Leituras seguem funcionais no servidor read-only antes/depois do worker GC, mas este teste curto não é medição de disponibilidade/latência nem prova de overlap de requests com cada passo do GC.

## Recuperação sem dependência da origem

Export OCI layout é empacotado em tar privado e criptografado pelo helper age já testado. O teste então encerra a origem e remove **storage original, layout seed, exports antes/depois do GC e tar plaintext original**, apenas caminhos sintéticos que ele criou. Backup age e descritor/digest esperado são o material restante da prova.

Age é autenticado completamente antes de entregar o tar ao ORAS. Em novo filesystem de registry vazio, `oras cp --from-oci-layout recovered.tar:multi` reconstrói o índice/manifests/configs/layer. Nova resolução preserva digest raiz, e nova exportação passa na verificação de todos os seis blobs.

ORAS seleciona também cada plataforma `linux/amd64` e `linux/arm64` a partir do registry restaurado; cada grafo selecionado contém exatamente manifest, config e layer, com os mesmos digests. Isso comprova conteúdo OCI multiplataforma, **não** pull/runtime Docker nem execução da imagem.

## Limites e trabalho ainda obrigatório

- Fixture local no mesmo host, backup age local; não upload S3 do export OCI nem verificador externo independente.
- Chave efêmera em memória, sem recovery kit persistente ou manifest autenticado do backup completo.
- Tar/staging plaintext existem no teste e são privados; quotas/reserva de disco, limpeza após morte do processo e interpretação de arquivos externos não são adapter de produção.
- Arquivos de export são regulares, próprios e limitados. Não anunciar esse empacotador/verificador de teste como validador geral seguro de arquivos arbitrários enviados por clientes.
- Sem gate de revisão/manifest, quotas, autorização de mount em duas pontas, concorrência de revogação no commit, reconciliação global/tags/referrers, coordenação durável SQL/OCI/GC ou restore de credenciais/políticas.

ADR e aceite OCI permanecem pendentes. Não substituir o contrato de pins/leases/barreira de produção pelo procedimento de manutenção read-only demonstrado aqui.

## Verificação

`GOPROXY=off GOSUMDB=off GOMAXPROCS=4 make verify` completo passou: build sem CGO, formatação, vet normal/com integração, sintaxe Bash, testes sem cache, todas as integrações repetidas três vezes e race detector. Binários/caches/imagens estavam previamente preparados; não é prova de instalação offline ou egress do produto.
