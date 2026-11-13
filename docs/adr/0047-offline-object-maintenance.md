# ADR 0047 — Manutenção offline de objetos: migração e coleta física

- **Status:** Implementado
- **Data:** 2026-11-12

## Contexto

Trocar o storage de filesystem para S3 deixava os objetos antigos ilegíveis, e nada apagava objetos sem referência: a coleta de blobs OCI e a expiração de uploads só removem linhas, porque o object store não participa das transações e a deduplicação por workspace compartilha objetos entre formatos. Apagar com o servidor no ar exigiria leases ou pins para não correr com um upload que está prestes a referenciar o mesmo digest.

## Decisão

Fazer as duas operações **offline**, com o servidor parado, em vez de introduzir leases agora.

- **Lock de instância.** O `serve` segura um `flock` exclusivo em `<data>/registry.instance.lock` durante toda a vida; os comandos abaixo tentam o mesmo lock e falham se ele estiver ocupado. Ele só exclui processos do mesmo host e mesmo diretório de dados: com PostgreSQL e mais de um host, pare todos os `serve`.
- **`registry migrate-objects`.** Com `REGISTRY_STORAGE_DRIVER=s3` configurado, copia todos os objetos de `<data>/object-store` para o bucket, verificando o SHA-256 na leitura e na escrita, e para no primeiro objeto corrompido. Pode ser repetido. Não apaga a cópia local: remova `<data>/object-store` depois de conferir.
- **`registry collect-objects [--apply]`.** Lê, numa transação de leitura, todas as colunas que nomeiam objetos (arquivos e sessões genéricos, Go, Cargo, npm e Pub em qualquer estado, pertença de blobs OCI e referências de manifests) e lista o storage configurado. Sem `--apply` só informa; com `--apply` apaga os objetos sem nenhuma referência e com mais de 24 h. Referências em qualquer estado são mantidas — upload expirado, revisão rejeitada —, o que desperdiça espaço mas nunca perde dados. Recusa rodar se o schema não for exatamente a versão que conhece (v44), porque uma versão nova pode referenciar objetos em tabelas que ela não lê.

Fluxo recomendado: a coleta horária do OCI e as expirações liberam as linhas; periodicamente, numa janela de manutenção, `collect-objects`, depois `collect-objects --apply`.

## Limites

Exige parada do serviço. Uma instalação grande lista todo o bucket e carrega o conjunto de referências em memória. Não há modo online; ele continua dependendo de leases.

## Evidência

`internal/objectmaint` em SQLite e PostgreSQL (dry run, remoção só do órfão antigo, preservação do referenciado e do recente, carência mínima, recusa de schema desconhecido, cópia verificada, repetível e interrompida por objeto adulterado) e lock exclusivo; `cmd/registry` com publicação npm em filesystem, `migrate-objects` duas vezes, remoção da cópia local, `serve` em S3 entregando o tarball com a integridade original e `collect-objects` recusado com o servidor no ar. Três repetições com race.
