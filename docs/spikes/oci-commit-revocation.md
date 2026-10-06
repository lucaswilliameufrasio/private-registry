# Spike 0.9 — revogação concorrente ao commit OCI

**Data:** 05/10/2026

**Estado:** janela de autorização obsoleta reproduzida determinísticamente. **Não resolvida**; coordenação de commit/revogação permanece requisito de aceite OCI.

## Reprodução

```sh
GOMAXPROCS=4 make setup-oci
GOMAXPROCS=4 go test -tags=integration -count=3 -run '^TestOCIRevocationBetween' -v ./internal/spikes/ociprobe
GOMAXPROCS=4 make verify
```

Distribution 3.1.2 e ORAS 1.3.4 existentes. ORAS publica um artefato baseline com blobs válidos; requisição HTTP OCI publica o mesmo manifest sob tag nova. Dados/storage/sockets próprios, servidor em Unix socket privado e proxies loopback. Sem imagens públicas, conteúdo executado ou mudança de Floci.

## Experimento e resultados

Permissão sintética atual em flag atômica; o teste não implementa JWT/RBAC. Dois proxies controlam a fronteira gateway→motor sem modificar o Distribution. Channels sinalizam que a requisição foi autorizada, mas ainda não chegou ao motor; GET direto no storage confirma tag ausente antes da revogação. A revogação é aplicada e reconhecida antes de liberar o encaminhamento. Não depende de sleeps aleatórios para criar a corrida.

| Cenário | Pausa controlada | Resultado após revogar |
|---|---|---|
| Checar uma vez | Gateway, após autorização | **201**, tag publicada e bytes do manifest conferidos |
| Revalidar antes de encaminhar | Gateway, antes da segunda checagem | **403**, tag continua ausente |
| Revalidar antes de encaminhar | Upstream, após segunda checagem e antes do motor | **201**, tag publicada e bytes conferidos |

Todos os casos foram repetidos contra o motor real. Os dois 201 são **caracterização da lacuna**, não testes de aceite de segurança. O caso 403 prova a utilidade da revalidação no ponto certo, mas não a atomicidade com o commit no processo externo.

## Consequência para o contrato

Consultar estado atual por requisição e imediatamente antes do encaminhamento é necessário, mas não resolve sozinho a ordem entre revogação e commit remoto. Pode haver autorização válida na checagem, revogação reconhecida enquanto o request está em trânsito/processamento e publicação posterior no motor.

Não declarar revogação imediata de commits já em voo com base nos spikes 0.5/0.7. Não oferecer direito adquirido às políticas do recebimento, nem declarar um segundo `Load`/SELECT como barreira transacional entre SQL e Distribution.

A implementação ainda precisa de um contrato explícito de coordenação/ordenação e tratamento de commit remoto incerto: quando a revogação é reconhecida, quais commits podem concluir, como se reconciliam resultados, como se preserva alcance publicado, e como se impede bypass após restart. Pequenas barreiras podem existir conforme o plano, mas devem ter duração/impacto medidos e estado/recuperação adequados. Cancelar uma conexão não prova que o motor não commitou.

Não foi adotado lock local, lease em memória ou backend alternativo como solução de produção neste spike. ADR/aceite do motor continuam abertos; coordenação durável, quotas, Docker real, revisão/alcance e backup/GC completo permanecem obrigatórios.

## Limites

O upstream é um intermediário de teste com pausa deliberada, não simulação do storage: o commit/consulta ocorrem no Distribution real. As permissões são inputs sintéticos e a publicação concorrente usa HTTP OCI, não push concorrente de cliente Docker. Não prova garantias multi-host, crashes, latência ou semântica de cancelamento/retry. Credenciais e autoaprovação reais seguem em outro trabalho.

## Verificação

`GOPROXY=off GOSUMDB=off GOMAXPROCS=4 make verify` completo passou: build sem CGO, formatação, vet normal/integration, sintaxe Bash, testes sem cache, integrações reais três vezes e race detector. Testes de caracterização verdes não significam que a lacuna de segurança foi resolvida. Binários/caches/imagens previamente preparados não provam instalação offline/egress do produto.

Continuação 0.9 posterior ao commit/push `136d61c`, ainda não commitada.
