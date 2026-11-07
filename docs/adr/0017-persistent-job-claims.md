# ADR 0017 — Fundação da fila persistente de jobs

- **Status:** Decisão para a fundação; worker, agendamento, outbox e operação ainda pendentes
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

Esta decisão não implementa, por si só, scheduler periódico, outbox transacional, UI, retry manual autorizado, alertas, prioridade sob pressão nem workers. Expiração de upload e GC não são automaticamente executados apenas porque a fila existe. Qualquer worker precisa tratar cancelamento, shutdown e operações parcialmente concluídas. Backup e GC exigem coordenação adicional específica; uma lease genérica não prova consistência de storage.

## Alternativas

- Timer local sem persistência: não recupera trabalho aceito após restart.
- Fila externa obrigatória: adiciona infraestrutura não exigida pelo plano de instância única.
- Prometer exatamente uma execução: não é possível para efeitos externos apenas com transações do banco local.
