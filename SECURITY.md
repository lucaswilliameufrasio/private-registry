# Segurança

## Versões suportadas

O projeto ainda não tem versões publicadas. Só o branch `main` recebe correções; não há backport. Veja [docs/production.md](docs/production.md) antes de rodar o registry com dados reais.

## Como reportar uma vulnerabilidade

**Não abra issue, discussão ou pull request público.** Use o reporte privado do GitHub: aba **Security** do repositório → **Report a vulnerability**.

Inclua, se puder:

- a versão (commit) e a configuração relevante, sem segredos;
- o impacto: o que um atacante consegue fazer e com qual acesso;
- os passos para reproduzir ou uma prova de conceito mínima.

## O que esperar

- Confirmação de recebimento em até 7 dias.
- Uma avaliação inicial e um plano de correção em até 30 dias, conforme a gravidade.
- Crédito no aviso de segurança, se você quiser.

Este é um projeto mantido por uma pessoa, sem programa de recompensa.

## Escopo

Estão no escopo o código deste repositório e a configuração padrão descrita na documentação. Ficam fora: vulnerabilidades em dependências já publicadas upstream (reporte ao projeto delas), ataques que exigem acesso de administrador ou ao servidor, e configurações que a documentação marca como inseguras ou só para desenvolvimento, como SMTP sem TLS.
