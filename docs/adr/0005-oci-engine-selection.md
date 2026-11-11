# ADR 0005 — Seleção do motor OCI

- **Status:** Bloqueado para motor externo — nenhum motor aceito; adapter próprio experimental no [ADR 0044](0044-own-oci-adapter.md)
- **Data:** 2026-10-12

## Contexto

OCI precisa de push/pull real, multiplataforma, autorização por workspace/repository, revisão, quotas, revogação, export/restore e GC. A direção inicial avalia CNCF Distribution em processo/container separado e atrás de gateway; o motor não pode ser exposto diretamente. O estado de alcance publicado e as permissões atuais precisam continuar autoritativos após restart e recovery.

Spikes 0.5–0.12 exercitaram Distribution/ORAS, gate de alcance, mount, recuperação, concorrência SQLite e lock PostgreSQL. Eles também reproduziram que revalidar no gateway antes do dispatch não impede que o motor commit depois de revogação reconhecida enquanto o request está em voo. Provas SQL isoladas não constituem coordenação transacional com o commit remoto.

## Decisão atual

- Não aceitar Distribution, gateway ou qualquer motor OCI como escolha de produção neste momento.
- Manter Distribution 3.1.2 + ORAS 1.3.4 apenas como candidato de spike, acessível somente através das fixtures/gate controlados; não anunciar suporte OCI.
- Não contornar a corrida adicionando um segundo `SELECT`, lock em memória, cancelamento de conexão ou reportando sucesso antes de persistir elegibilidade.
- A implementação OCI e o encerramento da fase 0 ficam bloqueados até um contrato e prova reproduzível de commit/revogação, incluindo timeout/resultado incerto e recuperação após crash. Se a fronteira remota não puder preservar a garantia, avaliar adapter OCI próprio ou backend que permita commit transacional controlado.

Esta é uma decisão de **não adoção atual**, não uma seleção definitiva de tecnologia nem adiamento do requisito OCI da v1.

## Alternativas consideradas

- **Aceitar Distribution atrás de gateway com checagem atual por request:** rejeitada; a corrida 0.9 a reproduz.
- **Aceitar o protótipo SQLite de receipt/alcance como solução:** rejeitada; ele não ordena o commit remoto, não cobre crash/multi-host nem implementa schema/RBAC produtivos.
- **Adotar adapter OCI próprio imediatamente:** ainda não decidido; pode mover commit/tag/visibilidade para transação local e ocultar blobs pendentes, mas demanda spike separado de compatibilidade, storage e protocolo real.
- **Aceitar race como limitação de v1:** rejeitada; revogação e isolamento são requisitos obrigatórios e não podem ser reduzidos silenciosamente.

## Condições para reabrir

1. Definir o instante de acknowledgment da revogação e quais commits em voo podem terminar antes dele.
2. Serializar publicação/revogação com estado durável compartilhado; preservar recuperação fail-closed se o upstream commitou mas o receipt/SQL commit ficou incerto.
3. Exercitar corridas com Distribution real e o mecanismo escolhido, inclusive policy revocation em cada janela, timeout, reinício/crash, retry idempotente e acesso por tag/digest/blob/HEAD/mount/referrer.
4. Comprovar que conteúdo pending/rejected não fica acessível por nenhuma rota, inclusive cross-repository mount e digest conhecido; backup e GC não apagam material protegido.
5. Validar PostgreSQL real, mecanismo SQLite do produto, cliente Docker e índice multiarch, quotas, revisão, restore sem origem e GC/pins coordenados.
6. Produzir teste de aceite que exige exatamente a ordem permitida, não apenas caracteriza 201 após revogação.

## Evidência

- [Spike 0.9 — commit/revogação](../spikes/oci-commit-revocation.md)
- [Spike 0.10 — receipts e alcance persistido](../spikes/oci-durable-release.md)
- [Spike 0.11 — ordenação SQLite](../spikes/oci-release-ordering.md)
- [Spike 0.12 — ordenação PostgreSQL](../spikes/postgres-release-ordering.md)
- [Plano — compatibilidade OCI](../development-plan.md#76-dockeroci)
- [Modelo de ameaças inicial](../threat-model.md)
