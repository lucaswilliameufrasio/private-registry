# Spike 0.5 — Distribution/ORAS e fronteira de revogação OCI

**Data:** 05/10/2026

**Estado:** publicação/consumo de artefato OCI e controles básicos comprovados; gateway completo, Docker/multiplataforma, quotas, revisão, backup e GC **pendentes**. Motor ainda não aceito para produção.

## Reprodução

```sh
GOMAXPROCS=4 make setup-oci
GOMAXPROCS=4 go test -tags=integration -count=1 -v ./internal/spikes/ociprobe
GOMAXPROCS=4 make verify
```

- CNCF Distribution **3.1.2**, release Linux amd64/arm64 com checksum fixado no setup. Fonte: [release](https://github.com/distribution/distribution/releases/tag/v3.1.2).
- ORAS CLI **1.3.4**, instalado com versão Go module fixada fora do repositório.
- Biblioteca JOSE/JWT **go-jose v4.1.5**, sem criptografia JWT caseira.

Tools ficam em `/tmp/opencode/private-registry-oci-tools`. Setup baixa/compila somente quando ausentes ou versão diferente. A preparação exige rede; com binários e dependências preparados a fixture não precisa acessar registries públicos. Isso não é instalação offline do produto. Atualmente fixture do servidor apenas Linux amd64/arm64; não implica suporte operacional dos clientes da publicação.

## Isolamento

Registry é subprocesso próprio, filesystem sintético em diretório exclusivo 0700, Unix socket privado 0600, **sem listener TCP** do motor. Gateway/token endpoint de teste fica em HTTP loopback com porta efêmera. Host/location do registry aponta para esse gateway; redirects de storage estão desativados. O processo recebe ambiente restrito, `GOMAXPROCS=2`, limite Go de memória 256 MiB (não limite rígido RSS/cgroup) e telemetry SDK desativado. Encerrar somente subprocesso criado e remover somente seus arquivos.

O Unix socket protege contra acesso remoto ao motor, não contra operador/processos com o mesmo usuário Unix. HTTP claro é exclusivo do loopback da fixture, não configuração TLS operacional. Motor/storage não usam Floci nesta primeira fatia OCI: filesystem do Distribution é distinto do CAS. S3 de desenvolvimento do projeto continua Floci, sem MinIO.

## Evidência de cliente/protocolo reais

ORAS faz login com credencial sintética pelo stdin e arquivo de credenciais exclusivo da fixture, push de `payload.txt`, pull para novo diretório e comparação byte a byte. Não executa conteúdo enviado e não usa imagem de produção.

Distribution valida JWT ES256 assinado pela chave efêmera confiada por certificado local: issuer, audience/service, validade e acesso `repository:<nome>:pull,push`. Testes reais incluem:

- pull privado anônimo negado;
- HEAD de manifest permitido ao leitor;
- token pull-only negado no início de upload;
- issuer/audience/repositório incorretos, token inválido ou expirado negados;
- Location de upload permanecendo na origem do gateway;
- leitor não afetado permanece disponível após revogação de publicador.

É artefato OCI ORAS, não prova de pull Docker de imagem executável, manifests/indexes multiplataforma, referrers, assinatura ou SBOM. Não extrapolar o sucesso.

## Revogação: limite nativo e gate experimental

1. Emitir JWT de 5 minutos e iniciar upload com esse token.
2. Revogar a conta sintética no emissor; novas emissões passam a falhar.
3. O Distribution **continua aceitando pull com JWT em cache**. Desabilitar emissão não revoga tokens existentes; validação nativa usa claims assinadas e tem leeway temporal próprio (60 segundos no código da versão estudada).
4. Ativar checagem experimental por requisição no gateway: verificar JWT com chave/issuer/audience esperados e consultar estado atual da conta.
5. O mesmo JWT recebe 403 no pull e na finalização do upload previamente iniciado; leitor não afetado continua com HEAD 200.

Regressão comprovada: comparação case-sensitive de `Bearer` permitia contornar o gate usando `bearer`. O teste falhou com essa comparação e passou com reconhecimento case-insensitive, compatível com o motor.

Esse gate e emissor existem **somente dentro do teste**. São uma prova de mecanismo com uma conta/repositório e estado atômico em memória; não implementação de RBAC, auditoria, account linking, token service de produção, leases ou sincronização. Revogação da conta antes da nova requisição de commit foi provada; mudança de autorização **durante** a mesma requisição upstream ainda exige coordenação/barreira no commit, não promessa derivada do teste.

## Aceite ainda aberto

Não marcar ADR/escolha do motor nem suporte OCI como concluídos. Faltam gate de manifest/publicação pendente, autorização atual por namespace/action, quotas (inclusive uploads interrompidos), revogação/concorrência durante commit, cross-repository mount autorizado nos dois lados, imagens Docker/multiplataforma/referrers, export/restauração alcançável e GC coordenado com backups/publicação. Projeção da UI não substitui manifests/blobs reais.

Próxima fatia deve testar inventário/export/restauração e GC sem apagar blobs alcançáveis, além de fechar os controles pendentes. Se as garantias falharem, registrar decisão antes de adotar backend alternativo, sem bypass silencioso ou adiamento de requisito v1.

Export/restauração de uma raiz OCI amd64/arm64 e GC conservador read-only avançaram posteriormente no [spike 0.6](oci-recovery-gc.md). Não concluem inventário global, coordenação online durável ou o aceite do motor; os limites acima permanecem explícitos.

## Verificação

`GOPROXY=off GOSUMDB=off GOMAXPROCS=4 make verify` completo passou: build sem CGO, formatação, vet normal e com integração, sintaxe Bash, testes sem cache, integrações reais repetidas três vezes e race detector. Binários, imagens e caches estavam previamente preparados; isso não prova instalação offline ou egress deny-by-default do produto.
