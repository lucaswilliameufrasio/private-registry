# ADR 0006 — Fronteira de publicação Hex

- **Status:** Aceito para o primeiro caminho; endpoint nativo ainda não aceito
- **Data:** 2026-10-12

## Contexto

Mix/Hex separa o Repository assinado, consumido por clientes, da HTTP API usada para publicar e administrar pacotes. Configurar um endpoint estático de leitura não torna o registry um servidor de publicação. O spike 0.17 comprovou consumo assinado, autenticação do fixture, resolução transitiva e rejeição de metadata alterada com Mix/Hex reais.

## Decisão

- A fonte prepara o tarball com `mix hex.build` e publica explicitamente esse artefato pelo API/CLI do registry.
- O registry valida tarball, nome/versão/metadata, imutabilidade e autorização; gera os recursos do Repository assinado e os disponibiliza a Mix/Hex.
- Não prometer compatibilidade `mix hex.publish` nem inventar flags/configuração. Suporte nativo só será anunciado se o endpoint, autenticação, resposta, atualização assinada e comportamento de aprovação forem comprovados com o cliente real.
- Chaves de assinatura do Repository são estado recuperável; rotação precisa preservar a confiança dos consumidores e backups. Este ADR não escolhe ainda o armazenamento operacional de chaves.

## Alternativas consideradas

- **Repository estático somente leitura como publicação Hex completa:** rejeitada; o fluxo cliente não envia o pacote ao Repository read-only.
- **Executar `mix hex.build` no servidor:** rejeitada; o registry recebe bytes preparados pela fonte e não executa toolchain/código do publicador.
- **Usar `mix hex.publish --repo` sem verificar suporte:** rejeitada; não assumir opção que pode não existir no cliente.
- **Bloquear Hex por não ter API nativa comprovada:** rejeitada como redução de escopo; o caminho explícito API/CLI continua obrigatório para a v1.

## Consequências e trabalho restante

- Implementar contrato autenticado e idempotente de upload de tarball, ACL, version reservation, validação, revisão/receipts, quota, audit e feedback de erro.
- Gerar `public_key`, registry e artifacts assinados de forma consistente; garantir que backup/restauração preserve ou reestabeleça trust/key rotation.
- Testar dependência privada transitiva com `repo` explícito na declaração do pacote; o spike observou que Mix não herdou o nome do repository no fixture.
- Testar clientes e versões fixadas, cliente nativo quando viável, Rebar3/docs separadamente; registrar qualquer limitação visível.
- Não marcar fase Hex concluída enquanto API/CLI de publicação, consumo real, assinatura, isolamento e recovery não forem aceitos.

## Evidência

- [Spike 0.17 — consumo Hex assinado](../spikes/hex-signed-registry.md)
- [Plano — Hex](../development-plan.md#75-elixirerlang-hex)
- [ADR de backup e restore](0003-backup-and-restore-boundaries.md)
