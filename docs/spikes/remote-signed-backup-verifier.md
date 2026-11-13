# Spike 0.15 — verificador externo busca backup assinado no Floci

**Data:** 09/10/2026

**Estado:** composição local de fixture SQLite → age → S3/Floci → receipt remoto assinado → GET/verificação em subprocesso comprovada. Não é verificador operacional nem backup completo da instalação.

## Reprodução

```sh
GOMAXPROCS=4 go test -tags=integration -count=3 -run '^TestExternalRemoteVerifierFetchesAndAuthenticatesFlociBackup$' -v ./internal/spikes/sqlitebackup
GOPROXY=off GOSUMDB=off GOMAXPROCS=4 make verify
```

Floci 2.1.0 fixado por digest, AWS SDK S3 real, SQLite/age reais e subprocessos do executável de teste. Credenciais explícitas do Floci `test/test`; bucket, container, portas e dados próprios. Container tem 2 CPUs/512 MiB, publicação só em loopback, sem mounts/Docker socket e cleanup pelo ID exato da fixture. O daemon Docker verificado para esta execução é rootless. Floci é emulador, não prova AWS/R2, atomicidade S3 real nem egress deny-by-default.

## Fluxo comprovado

1. Processo produtor recebe recipient público age e chave privada Ed25519 de assinatura; a identidade X25519 privada de recovery não é entregue a ele.
2. Cria SQLite sintético e snapshot online; cifra o snapshot e calcula seus digests.
3. Envia ciphertext ao objeto S3, depois publica envelope/receipt assinado em objeto separado, como último marcador da fixture. Ambos usam `If-None-Match: *`; a atomicidade concorrente dessa condição não é afirmada.
4. Produtor remove snapshot/origem/ciphertext locais antes de terminar. No sucesso, o diretório do produtor fica vazio. Um objeto sem receipt publicado não é aceito pelo verificador; falha parcial remota e reconciliação continuam fora da prova.
5. Processo verificador separado lê chave pública e instalação/backup esperados de config local confiada, limitada e não gravável por grupo/outros. Envelope não fornece trust anchor. O verificador busca primeiro o receipt remoto, rejeita envelope não canônico/oversized e verifica assinatura/contexto antes de buscar o ciphertext.
6. Busca ciphertext por GET S3 em arquivo temporário privado, limita a 2 MiB, confere tamanho e SHA-256 assinado, autentica todos os chunks age **antes de abrir SQLite**, confere digest plaintext, `integrity_check`, foreign keys, 128 linhas/262144 bytes e remove ciphertext/plaintext temporários antes de responder sucesso.

Sucesso observado com PIDs distintos: produtor enviou backup/receipt; cópia local do produtor foi removida; verificador buscou ambos no Floci e restaurou 128 linhas. Staging privado ficou vazio. O envelope deixa de vir pelo stdin do verificador; apenas configuração S3 do fixture e identidade age privada chegam via stdin, enquanto trust store vem por caminho separado em ambiente/configuração local do subprocesso.

## Rejeições no processo verificador

- Receipt adulterado, assinatura ausente, JSON malformado, desconhecido ou acima de 8 KiB.
- Chave pública não confiada, outra instalação ou outro ID de backup esperado.
- Receipt/ciphertext remoto ausente.
- Ciphertext de mesmo tamanho mas digest diferente, e objeto maior do que o tamanho assinado.
- Ciphertext adulterado ou truncado **com digest/tamanho atualizados e novo receipt válido assinado pelo fixture**: passa o vínculo/digest e é rejeitado pela autenticação age.

Em falhas não há relatório JSON de sucesso e o staging do verificador é removido. Os testes exercitam o caminho de cliente AWS SDK contra Floci; não usam mock S3.

## Limites e gaps não resolvidos

- Apenas snapshot SQLite sintético. Sem PostgreSQL neste processo, OCI, blobs de formatos, configuração, segredos, chaves internas, inventário, pins, GC ou manifest completo da instalação.
- Receipt fixa instalação/backup, plaintext/ciphertext digests e tamanho; **não inclui chave/path do objeto**, versão de schema/app, conjunto de artefatos, recipient ID, timestamps/freshness ou estado anti-replay. O teste conhece os object keys separadamente.
- Verificador no mesmo host/usuário e binário/código da fixture; separar PID/inputs não constitui sandbox, isolamento contra processo do mesmo usuário nem implementação criptográfica independente. Relatório continua JSON não assinado/não autenticado.
- Trust config é arquivo local de teste, sem instalação/rotação/revogação de chaves operacional; identidade age vem do controlador por stdin. Não entrega recovery kit offline nem scheduler externo.
- Sem crash/SIGKILL cleanup, jobs persistentes, leases/pins, retry/reconciliação de upload parcial, prune/retenção, validação de todos objetos ou smoke tests dos sete formatos.
- O servidor não está isolado de egress por esta fixture. Só o helper de client S3 restringe endpoint a IP literal loopback e credenciais explícitas; isso não implementa política de rede de produção.
- Floci 2.1.0 tem gap conhecido de dois vencedores em multipart condicional. Esta prova usa `PutObject` pequeno, sequência única e não esconde nem resolve o gap de atomicidade concorrente de storage real.

Portanto, não marcar o requisito de verificador externo automático/manual, backup completo, primeira validação de prontidão, recovery em host novo, instalação offline ou fase 0 como concluídos.

## Verificação

`GOPROXY=off GOSUMDB=off GOMAXPROCS=4 make verify` passou: build sem CGO, formatação integral, vet normal/integration, sintaxe Bash, testes unitários sem cache, integrações SQLite/PostgreSQL/Floci reais três vezes e race detector. As imagens/dependências já estavam preparadas; isso não prova instalação offline do produto. Floci foi executado no daemon rootless disponível.
