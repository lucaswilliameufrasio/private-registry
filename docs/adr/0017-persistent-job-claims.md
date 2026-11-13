# ADR 0017 — Fundação da fila persistente de jobs

- **Status:** Fundação e worker limitado de expiração de uploads; outbox e operação ainda pendentes
- **Data:** 2026-11-06

## Contexto

O plano exige trabalho recuperável após restart, leases, retries e dead-letter. A expiração de uploads já tem uma operação em lote, mas chamá-la por um timer em memória não implementaria essas garantias nem a fila comum.

## Decisões

- Persistir jobs e contadores de tentativa no banco da instalação, com identidade e chave de idempotência explícitas. O mesmo job não é recriado silenciosamente após conclusão ou dead-letter.
- Usar timestamps UTC inteiros e transações curtas. A coordenação existente da linha da instalação serializa mutações nos dois bancos; PostgreSQL usa lock de linha e SQLite usa escrita transacional. Isso favorece correção na instância única prevista, não throughput distribuído.
- Cada claim recebe token aleatório novo e prazo finito. Heartbeat, sucesso e falha exigem o token vigente e lease ainda válida; um worker atrasado não pode finalizar trabalho retomado por outro.
- A execução é pelo menos uma vez: chamadas externas e seus efeitos exigem idempotência própria. Expiração de lease consome uma tentativa; esgotamento leva a estado dead-letter, não a sucesso.
- Payload é pequeno e não deve conter credenciais, tokens ou dados sensíveis. A fila não representa uma solução de armazenamento de segredos.

## Limites e trabalho posterior

O servidor inicia um worker único para expiração de uploads: existe um registro recorrente fixo, claim com lease de 30 segundos, operação limitada a 10 segundos e até 128 sessões, reagendamento por minuto e retry com backoff e jitter. O worker para ao cancelar o servidor; após interrupção, uma lease expirada permite retomada. O job é idempotente e não remove objetos. Ao esgotar oito tentativas, fica em dead-letter e o worker registra erro.

O administrador ativo pode listar metadados limitados em `GET /api/v1/admin/jobs/dead` e reenfileirar `expire-generic-uploads` via `POST /api/v1/admin/jobs/{jobID}/retry`, com MFA recente, CSRF, `expected_revision` e auditoria transacional. A revisão muda em cada transição de lease/estado, impedindo que uma tela antiga reenvie um job que voltou a falhar. Outras espécies de job aparecem apenas como `other` e não podem ser reprocessadas por essa rota até que seus efeitos e autorização tenham política própria. O código de falha é apenas `operation_failed`, `lease_expired` ou `unknown` para registros históricos; não contém mensagem bruta nem prova causa-raiz. Payload, chave de idempotência e lease nunca são retornados. A listagem é paginada; UI e alertas operacionais continuam pendentes.

Esta implementação não entrega scheduler genérico, outbox transacional, UI, alertas, prioridade sob pressão, nem GC ou limpeza de staging. Backup e GC exigem coordenação adicional específica; uma lease genérica não prova consistência de storage. O agendamento recorrente expira sessões, não limpa objetos órfãos, e não é garantia de execução pontual sob falha ou indisponibilidade.

## Alternativas

- Timer local sem persistência: não recupera trabalho aceito após restart.
- Fila externa obrigatória: adiciona infraestrutura não exigida pelo plano de instância única.
- Prometer exatamente uma execução: não é possível para efeitos externos apenas com transações do banco local.
