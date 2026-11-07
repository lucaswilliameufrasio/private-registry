# ADR 0019 — Driver S3 de conteúdo: qualificação inicial

- **Status:** Implementação isolada em qualificação; não conectada ao servidor e não aceita para produção
- **Data:** 2026-11-07

## Contexto

O storage S3 compatível deve preservar os invariantes do driver local: namespace por workspace, imutabilidade por SHA-256, streaming limitado e verificação antes de disponibilizar bytes. O backend não participa da transação SQL. Floci é fixture; o spike de backup demonstrou que sua conclusão multipart condicional não é prova de atomicidade de S3 real.

## Decisões para a primeira fatia

- O cliente S3 é injetado: o driver não lê credenciais globais, não descobre endpoints e não decide autenticação ou egress. A configuração produtiva, seleção do driver e acesso a segredos ficam para outra entrega.
- Fazer staging privado limitado em disco, calcular SHA-256 localmente e usar `PutObject` condicional `If-None-Match: *`. Isso é distinto do multipart problemático no spike; não extrapolar o resultado da fixture para qualquer backend. Conflito e resultado incerto só podem ser aceitos após baixar e verificar o objeto completo contra digest e tamanho esperados.
- Leitura, inclusive Range, baixa e verifica o objeto inteiro em staging privado antes de expor bytes; isso preserva integridade ao custo de espaço e latência. Não confiar em ETag como SHA-256. Cancelamento e erro limpam arquivos locais de staging controlados pela chamada.
- A API de storage não concede acesso e não autoriza exclusão; autorização, retenção, pins e GC continuam responsabilidade das camadas superiores. Um objeto remoto sem referência SQL continua órfão até haver reconciliação segura.

## Limites e aceites pendentes

Esta fatia não habilita S3 na instalação, não implementa multipart, recuperação de staging após crash, limites agregados de disco temporário, timeouts globais, gerenciamento de credenciais, política de egress, backup ou GC. Testes contra Floci e fixture HTTP não provam semântica de um serviço externo. Antes de habilitar o backend para uso real, testar criação condicional concorrente, integridade, falhas e resultados incertos no backend S3 real escolhido, com configuração segura e autorização explícita. As permissões do bucket devem impedir gravações que ignorem os controles de imutabilidade; um ator com acesso privilegiado ao bucket pode violar invariantes.

## Referências

- [AWS — conditional writes](https://docs.aws.amazon.com/AmazonS3/latest/userguide/conditional-writes.html)
- [ADR 0015 — storage filesystem](0015-content-addressed-filesystem-storage.md)
- [Gap de multipart condicional no Floci](../spikes/s3-backup.md)
