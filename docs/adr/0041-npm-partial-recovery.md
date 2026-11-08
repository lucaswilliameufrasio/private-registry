# ADR 0041 — Recovery npm parcial e isolado

- **Status:** Experimental; não constitui backup completo nem autoriza promoção
- **Data:** 2026-11-08

O inventário npm enumera versões e recibos verificados em uma transação de snapshot, deduplica por workspace e digest e rejeita tamanhos conflitantes. O conjunto npm assinado usa domínio distinto dos conjuntos genérico, Go e Cargo, e exige trust e contexto fornecidos independentemente. A captura verifica ciphertext e a restauração verifica o inventário do snapshot antes de restaurar objetos em destino novo e privado.

`PrepareEncryptedSQLiteNPMRecovery` compõe conjuntos genérico, Go, Cargo e npm, mantém `RECOVERY_INCOMPLETE`, invalida sessões e credenciais e suspende jobs na cópia. Caminhos que não recebem conjunto npm continuam recusando referências npm. A operação não recupera configuração, chaves internas ou outros formatos, não prova atualidade nem completude global e não promove a instalação. O chamador deve controlar staging, recursos e proteção contra GC.

## Evidência parcial

Testes com race repetidos três vezes em SQLite e PostgreSQL verificaram inventário, deduplicação, limites e rejeição de tamanhos conflitantes; Floci foi usado apenas como fixture. Uma composição SQLite com tarball npm realmente recebido e publicado testou recuperação cifrada, objeto remoto ausente, inventário assinado incompleto, chave incorreta, trust divergente e destino existente. Assinatura, payload ou signatário inválidos foram recusados antes de abrir ciphertext. O catálogo recuperado recusou credenciais antigas e permitiu leitura com grant e token novos; a origem permaneceu inalterada. Não há prova de restore integral, execução do servidor recuperado, PostgreSQL, verificador externo operacional, anti-rollback ou backend S3 real.
