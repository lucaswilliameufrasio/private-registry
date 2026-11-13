# ADR 0019 — Driver S3 de conteúdo: qualificação inicial

- **Status:** Selecionável no `serve` por configuração explícita; comprovado apenas contra Floci, sem qualificação de R2/B2/S3 reais
- **Data:** 2026-11-07

## Contexto

O storage S3 compatível deve preservar os invariantes do driver local: namespace por workspace, imutabilidade por SHA-256, streaming limitado e verificação antes de disponibilizar bytes. O backend não participa da transação SQL. Floci é fixture; o spike de backup demonstrou que sua conclusão multipart condicional não é prova de atomicidade de S3 real.

## Decisões para a primeira fatia

- O cliente S3 é injetado: o driver não lê credenciais globais, não descobre endpoints e não decide autenticação ou egress. A configuração produtiva, seleção do driver e acesso a segredos ficam para outra entrega.
- Fazer staging privado limitado em disco, calcular SHA-256 localmente e usar `PutObject` condicional `If-None-Match: *`. Isso é distinto do multipart problemático no spike; não extrapolar o resultado da fixture para qualquer backend. Conflito e resultado incerto só podem ser aceitos após baixar e verificar o objeto completo contra digest e tamanho esperados.
- Leitura, inclusive Range, baixa e verifica o objeto inteiro em staging privado antes de expor bytes; isso preserva integridade ao custo de espaço e latência. Não confiar em ETag como SHA-256. Cancelamento e erro limpam arquivos locais de staging controlados pela chamada.
- A API de storage não concede acesso e não autoriza exclusão; autorização, retenção, pins e GC continuam responsabilidade das camadas superiores. Um objeto remoto sem referência SQL continua órfão até haver reconciliação segura.

## Limites e aceites pendentes

Uma composição experimental separada cria o cliente com origem HTTPS, CIDRs e credenciais explicitamente fornecidos, sem proxy ou cadeia de credenciais padrão; DNS explícito é opcional para destinos por nome. A restrição não controla I/O realizado pelo provider de credenciais. Uma camada de admissão por instância mantém a vaga de leitura até `Close`, recusa sobrecarga e limita operações simultâneas; um upload pode precisar de dois arquivos de staging. O teto de bytes ativos calculado é `(2 × tamanho máximo + 1) × concorrência`, incluindo o byte de prova de overflow. Um timeout explícito envolve cada operação e preserva o contexto de leitura até `Close` ou expiração; não interrompe por si só um `Read` que ignore contexto e bloqueie indefinidamente. Leituras não fechadas ocupam a vaga, e falhas de limpeza ou crash podem deixar arquivos fora dessa contagem. Não é quota de filesystem, limite entre processos nem cleanup de crash. A composição passou três vezes com race em HTTPS sintético e Floci, sem credenciais reais.

Na leitura verificada, falha no fechamento do corpo remoto agora também impede a exposição do objeto e remove o staging; uma fixture com falha sintética de fechamento passou três vezes com race. Isso não demonstra comportamento de um backend remoto real.

Uma jornada HTTP genérica existente também foi executada com S3 injetado: autenticação, grants, upload, publicação, download e recusas passaram três vezes com race tanto em endpoint TLS sintético quanto em Floci isolado. A fixture usa SQLite; o teste Floci usa HTTP local, não o cliente HTTPS restrito. Isso não valida R2/B2, configuração do `serve`, semântica de uma rede real nem persistência remota durável.

Esta fatia não habilita S3 na instalação, não implementa multipart, recuperação de staging após crash, limites agregados de disco temporário, timeouts globais, gerenciamento de credenciais, política de egress, backup ou GC. Testes contra Floci e fixture HTTP não provam semântica de um serviço externo. Antes de habilitar o backend para uso real, testar criação condicional concorrente, integridade, falhas e resultados incertos no backend S3 real escolhido, com configuração segura e autorização explícita. As permissões do bucket devem impedir gravações que ignorem os controles de imutabilidade; um ator com acesso privilegiado ao bucket pode violar invariantes.

## Seleção pelo `serve` (2026-11-11)

`REGISTRY_STORAGE_DRIVER=s3` troca o object store de todos os formatos pelo driver S3 composto (cliente restrito → admissão → deadline). O default continua `filesystem`, e qualquer variável `REGISTRY_S3_*` sem o driver S3 é erro de configuração. São obrigatórios `REGISTRY_S3_ENDPOINT` (origem HTTPS, sem path), `REGISTRY_S3_REGION` (`auto` no R2), `REGISTRY_S3_BUCKET`, `REGISTRY_S3_ACCESS_KEY_ID_FILE`, `REGISTRY_S3_SECRET_ACCESS_KEY_FILE` e `REGISTRY_S3_ALLOWED_NETWORKS`; sem redes explícitas não há saída. Opcionais: `REGISTRY_S3_PREFIX`, `REGISTRY_S3_DNS_SERVER` (necessário para endpoint por nome), `REGISTRY_S3_CA_FILE` (substitui as raízes do sistema só nesta integração), `REGISTRY_S3_MAX_CONCURRENT` (default 8) e `REGISTRY_S3_OPERATION_TIMEOUT_SECONDS` (default 600).

As credenciais nunca vêm do ambiente: cada arquivo precisa ser regular, do usuário do processo, sem acesso de grupo/outros, sem symlink e com um único hard link; conteúdo vazio, com espaço interno ou com mais de uma linha é recusado na inicialização. O staging fica em `<data>/s3-staging`; o teto de operações ativas é `(2 × 1 GiB + 1) × REGISTRY_S3_MAX_CONCURRENT`, e arquivos órfãos após crash não são recolhidos automaticamente. O endereçamento é path-style.

Evidência: `TestServeS3StorageRealClientJourney` sobe o `serve` real configurado só por ambiente, publica e instala com npm real e confere que os bytes estão no bucket sob o prefixo, que `<data>/object-store` não foi criado e que o staging terminou vazio; passou três vezes com race, junto com as suítes do driver. O bucket é Floci atrás de um front TLS local.

Continua sem prova: escrita condicional `If-None-Match: *` e comportamento sob falha em R2, B2 ou S3 reais (um backend que ignore a condição enfraquece a imutabilidade para quem tem escrita no bucket, embora a leitura sempre reverifique o SHA-256); objetos grandes em links lentos (o cliente HTTP tem limite total de 2 minutos por requisição); multipart; GC de objetos órfãos; backup dos objetos remotos. O banco SQLite e o staging continuam em disco local.

## Referências

- [AWS — conditional writes](https://docs.aws.amazon.com/AmazonS3/latest/userguide/conditional-writes.html)
- [ADR 0015 — storage filesystem](0015-content-addressed-filesystem-storage.md)
- [Gap de multipart condicional no Floci](../spikes/s3-backup.md)
