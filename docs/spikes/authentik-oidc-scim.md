# Spike 0.18 — Authentik OIDC, SCIM e observabilidade de falha

**Data:** 13/10/2026

**Estado:** OIDC authorization-code + PKCE e SCIM básico reais comprovados em Authentik 2026.8.3. Sob falha HTTP 503, `sync/status` permaneceu `info`, o marcador de último sucesso não avançou e uma tarefa ficou `queued`, sem health utilizável. Sob recuperação, as repetições variaram entre retry de evento com atualização do perfil e full sync que leu Users sem `PUT/PATCH`, deixando drift; uma execução registrou uma atualização e correção do drift durante a janela da full sync, sem causalidade determinística demonstrada. Health/freshness e reconciliação autoritativa continuam gaps obrigatórios; a fase 0 não está concluída.

## Fixture e reprodução

O teste usa Authentik 2026.8.3 fixado pelo digest do índice multiarch `sha256:ab9b4e8cc4ab3f8d1198d2db6aeea66bafea1963b3f2843589e0d163f97d9849`, PostgreSQL 18.6 e Valkey 9.0.3 fixados por digest. O Compose limita CPU, memória e PIDs; os serviços ficam numa rede `internal`, sem portas publicadas nem Docker socket montado. O servidor SCIM sintético roda no container Authentik e só aceita dados/identidades sintéticos.

```sh
make setup-authentik
GOMAXPROCS=4 GOPROXY=off GOSUMDB=off go test -tags=integration -count=1 -v ./internal/spikes/authentik
```

O teste cria credenciais aleatórias num `.env` temporário com modo 0600, usa projeto Compose único e remove apenas os containers/rede/arquivo que criou. `contract_probe.py` chama APIs Authentik reais; `scim_target.py` implementa a fronteira SCIM da fixture e registra respostas/latências monotônicas. Não há endpoint de fixture exposto no host nem acesso a IdP/serviço externo durante o teste. A execução observada ocorreu em daemon Docker rootless.

## OIDC comprovado

- Cria provider público authorization-code, redirect URI estrito e cliente com PKCE S256; percorre identificação/senha no fluxo real do Authentik.
- Busca discovery e JWKS e verifica assinatura RS256 do ID token, além de issuer, audience, nonce e expiração.
- Para a mesma conta sintética, `sub` é igual ao `externalId` provisionado por SCIM e diferente do email mapeado. Isso demonstra uma configuração possível de identidade estável, não o mecanismo de vinculação do futuro registry.

O teste **não** implementa nem prova que o registry rejeitará auto-link por email, nem que todos os métodos de login, sessões ou tokens de uma conta desativada serão bloqueados.

## Provisionamento e mudanças SCIM comprovados

- Authentik envia Users/Groups ao target SCIM real da fixture. Para evitar a corrida observada quando duas associações de grupo eram alteradas ao mesmo tempo, o teste agora espera a primeira membership aparecer antes de adicionar a segunda; isso não comprova burst/concurrency semantics.
- Remover a associação da conta sintética ao grupo A removeu o membro de todas as cópias sintéticas desse grupo; a associação independente ao grupo B e a conta remota permaneceram. Em três repetições recentes, latências de remoção foram 0,234–0,471 s.
- Desativar a conta em Authentik enviou `active: false` sem login novo. Em três repetições recentes, latências foram 0,978–1,021 s.
- Uma full sync solicitada pela schedule SCIM terminou com `last_sync_status: info` e `last_successful_sync` preenchido.

O target SCIM sintético responde com sucesso a POSTs repetidos e não aplica unicidade por `externalId`. Nas três repetições, o relatório encontrou seis recursos de grupo sintéticos excedentes para os dois grupos de teste. As predicates agora procuram cópias com membership e a remoção exige que todas as cópias do grupo removido fiquem sem membros; isso evita depender da ordem de iteração, mas **não valida unicidade nem semântica de conflito/upsert de um servidor SCIM real**. O comportamento duplicado é evidência limitada da interação com esta fixture permissiva, não uma conclusão sobre todos os targets SCIM nem uma garantia do registry.

As latências são amostras de uma fixture local, não garantia universal de p95. A documentação do Authentik 2026.8 descreve envio incremental e reconciliação completa periódica (padrão horário); isso não substitui a meta do produto de aplicar mudanças normais em até 1 minuto. Fonte: [SCIM Provider](https://docs.goauthentik.io/add-secure-apps/providers/scim).

## Falha controlada e resultado negativo

O target foi configurado para responder HTTP 503; em seguida uma alteração de perfil numa conta desativada disparou sync por objeto. A fixture observou uma resposta 503. Após a janela de observação no Authentik fixado:

- `/providers/scim/{id}/sync/status/` ainda retornava `last_sync_status: info` e o mesmo `last_successful_sync` anterior;
- a tarefa de dispatch estava `done/info`, mas a tarefa de sync por objeto continuava `queued/queued`;
- nenhum log `warning`/`error` apareceu na API de tarefas naquela janela;
- portanto `health_failure_signal_observed` foi falso. `info` não pode ser tratado como prova de que todas as entregas SCIM recentes tiveram sucesso.

Depois de restaurar o target, o retry da tarefa de evento alterou o perfil remoto para o valor novo em execuções anteriores. Porém, uma repetição `-count=3` posterior observou dois resultados: em duas execuções, full sync leu `/Users`, enviou zero `PUT/PATCH` e deixou o drift; em uma, a tarefa de retry não reconciliou o evento, mas houve um `PUT/PATCH` e o drift foi corrigido durante a janela da full sync. A ordem/evento que causou a correção não é estável o bastante para atribuí-la a um reconciliador autoritativo. Portanto, **a full sync não oferece ainda uma garantia determinística de reconciliação**, embora uma execução tenha corrigido o drift. Retrys/backoff e sua previsibilidade continuam sem caracterização suficiente; também não há sinal health confiável para o bloqueio após 1 hora.

## Gaps obrigatórios para encerrar 0.18 e requisitos de produto

- Definir e testar um health/freshness monitor confiável para falhas de sync; não usar ausência de eventos nem `last_sync_status: info` isoladamente como sucesso.
- Caracterizar retry/backoff e health/freshness sem inferir sucesso de `info`; full sync variou entre zero atualizações e uma atualização acompanhada de drift corrigido, sem prova determinística de reconciliação.
- No registry ainda não existem o bloqueio humano após o default configurável de 1 hora, área de saúde/revisão, nem desbloqueio auditado após reconciliação bem-sucedida.
- Provar que reconciliação remove só bloqueios originados por indisponibilidade e respeita estado ativo, políticas/grants atuais e bloqueios por outras causas; não reativar sessões/tokens revogados.
- Provar bloqueio de senha, passkey, sessões, tokens pessoais e demais métodos vinculados; preservar conta local de emergência e contas de serviço independentes.
- Validar vinculação explícita por identificador estável sem auto-link por email, restrição de credencial SCIM e política de remoção seletiva de concessões no modelo do registry.
- O target usa HTTP em rede local da fixture; TLS, ACL/egress de produção, segredo operacional e comportamento de outros IdPs não foram aceitos.

Este spike é evidência parcial de fase 0, não servidor, integração de produção ou suporte anunciado. Não marcar a fase 0, a fase de identidade nem a v1 como concluídas.

## Verificação

A repetição `-count=3` observou a variação acima e invalidou o assert determinístico anterior. A fixture ficou limitada a 1 CPU para o worker e a espera de sync inicial foi ampliada de 120s para 240s; o erro agora informa as tarefas ainda bloqueadoras. Um gate falhou uma vez no race detector ao esperar membership do usuário de recuperação; após adicionar diagnósticos limitados e redigidos para tasks, a execução focalizada race passou e o `make verify` integral final também passou. A causa-raiz daquela falha não foi estabelecida; o resultado foi transitório, não uma correção de comportamento comprovada. O teste aceita ambos os resultados de full sync sem tratar nenhum como garantia de reconciliação. Grupos excedentes variaram (4–6), pois o target não rejeita POST duplicado.

Atualização em 22/10/2026: `TMPDIR=/home/lucaseufrasio/.cache/private-registry-race-tmp.ggcqJ3 GOMAXPROCS=4 PUB_TEST_DART_BIN=/home/lucaseufrasio/fvm/versions/3.47.7/bin/cache/dart-sdk/bin/dart make verify` passou build sem CGO, format-check, vet normal/integration, sintaxe Bash, unitários, integrações 3× e race 1×. O teste focalizado Authentik sob `-race` também passou. O diretório privado da fixture agora usa `TMPDIR` e faz fallback para `/tmp/opencode`. Uma execução race anterior falhou no provisionamento SCIM do usuário de recuperação; a falha não se repetiu depois da mudança, mas isso não demonstra sua causa-raiz. O target continua permitindo POSTs duplicados, e a evidência não aceita health/freshness ou reconciliação determinística nem prova operação offline do produto.
