# ADR 0003 — Fronteiras de backup e validação de restore

- **Status:** Direção aceita; formato completo, trust operacional e aceite de backend continuam pendentes
- **Data:** 2026-10-12

## Contexto

O backup v1 precisa restaurar uma instalação em host e storage vazios, sem depender do banco ou bucket de produção. Snapshot, configuração recuperável, chaves internas e todos os artefatos referenciados formam uma unidade lógica; upload concluído não significa backup validado.

Os spikes 0.1–0.4 comprovaram snapshots SQLite/PostgreSQL e transporte criptografado limitado. Os spikes 0.13–0.16 adicionaram receipts contextualizados/assinados e leitura/restore remoto em subprocessos separados. Nenhum cobre a instalação completa, inventário/GC coordenado, trust store operacional ou atomicidade S3 concorrente. Floci 2.1.0 aceitou dois vencedores numa corrida de conclusão multipart condicional.

## Decisão

- Usar `age` com recipients explícitos; não criar formato criptográfico próprio. O registry usa o recipient público para cifrar e não recebe a identidade privada de recovery por padrão.
- Separar confidencialidade da autenticidade: assinatura/receipt usa chave e trust anchor distintos da chave age. Trust e contexto esperados vêm de configuração recuperável independente do objeto remoto; o envelope não pode definir a própria chave confiável.
- Representar cada backup por manifest lógico versionado que identifica instalação e backup, engine/schema/app, captura/conclusão, objetos e digests/tamanhos, configuração recuperável, key IDs, dependências e estado de validação. O schema final ainda será definido antes da implementação produtiva.
- Publicar o manifest/marcador autenticado de conclusão somente depois de todos os objetos necessários serem enviados e verificados. Objeto parcial, receipt ausente ou upload ambíguo não é backup completo nem elegível para prune.
- Distinguir `completed` de `validated`. Validação exige GET remoto, autenticação completa do conteúdo e restauração real em banco/storage novos e descartáveis, seguida por checks de integridade e smoke tests dos formatos presentes.
- Oferecer validação manual com chave offline e verificador externo automático com chave protegida fora do registry. Verificador recebe somente acesso ao destino de backup e ambiente isolado; não acessa produção nem libera administração da instalação.
- Restore inicia em recovery mode, não reativa sessões/tokens por padrão, reconstrói referências antes de escrita e só promove o destino após validação explícita.
- A primitiva inicial `internal/backup.InventoryGeneric` enumera, a partir de uma transação de snapshot fornecida pelo chamador, objetos do catálogo genérico e recibos de upload, deduplicados por workspace e digest, com limite explícito e rejeição de tamanhos conflitantes. Ela não cria o snapshot nem protege objetos de GC, não verifica ou copia os bytes, e não abrange outros formatos. Não representa um manifesto completo nem um backup recuperável.
- `internal/backup.CopyGenericObject` copia um objeto inventariado com limite e verificação própria de tamanho e SHA-256. A saída permanece parcial e não confiável até o sucesso, inclusive fechamento da origem; o chamador deve descartá-la em caso de erro. A função não faz promoção atômica, cifragem, snapshot, pin ou restore.
- Um teste sintético compõe o spike de snapshot online SQLite com inventário e cópia para storage vazio: uma gravação posterior permanece na fonte, mas não entra no snapshot anterior; o catálogo do snapshot permite leitura com grant e nega um usuário sem grant. O teste usa diretamente o snapshot local e não inicia o servidor nem valida a revogação de credenciais após restore. Essa evidência local não implementa a coordenação com GC, cifragem, recuperação de chaves, PostgreSQL ou um backup completo.

## Alternativas rejeitadas

- **Copiar diretamente o SQLite ativo ou incluir apenas o `.db`:** não captura corretamente WAL/snapshot; usar API de backup.
- **Tratar envio, ETag ou sucesso de PUT como restore validado:** não prova autenticidade completa, completude nem que ferramentas e formatos recuperam.
- **Guardar a única chave de decriptação no registry ou dentro do backup cifrado:** cria dependência circular e falha junto da instalação.
- **Usar um hash simples como prova de origem:** detecta divergência contra valor confiável, mas não autentica quem emitiu o recibo.
- **Assumir commit transacional entre SQL e S3:** não há transação distribuída; estados, receipts, pins e reconciliação precisam tratar resultado incerto explicitamente.

## Consequências e decisões ainda abertas

- Fechar o schema/canonical encoding do manifest, assinatura e relatório autenticado; cobrir freshness, anti-rollback, rotação/revogação de trust e origem do signer.
- Definir armazenamento remoto imutável, criação condicional concorrente entre processos, retry/reconciliação, leases/pins, retenção e GC, incluindo aceitação estrita contra S3 real. Floci é somente fixture de desenvolvimento.
- Implementar inventário completo de banco, filesystem/S3, OCI e objetos por formato; locks/barreiras curtas de publicação e GC; recuperação pós-crash e espaço temporário limitado.
- Distribuir/verificar `pg_dump`/`pg_restore` da versão suportada, definir política de roles/owners e testar upgrade/recovery.
- O verificador externo precisa ser isolado por deployment e autenticar seu relatório; subprocesso no mesmo host/usuário não é sandbox de produção.
- Validar backup completo e recovery kit antes de permitir declaração de prontidão para produção. Este ADR não aceita nenhum dos spikes como backup v1.

## Evidência e referências

- [Plano — backups e restore](../development-plan.md#15-backups-online-criptografados-para-s3)
- [Spike SQLite + age](../spikes/sqlite-backup.md)
- [Spike de restore remoto SQLite](../spikes/remote-signed-backup-verifier.md)
- [Spike de restore remoto PostgreSQL](../spikes/postgres-remote-external-verifier.md)
- [Gap de multipart condicional no Floci](../spikes/s3-backup.md#gap-reproduzido-conclusão-concorrente-condicional)
- [Modelo de ameaças inicial](../threat-model.md)
