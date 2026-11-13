# ADR 0012 — Baseline de segurança do toolchain Go

- **Status:** Aceito
- **Data:** 2026-10-22

## Contexto

O projeto exigia Go 1.26.9 e preferia 1.27.2 após um advisory anterior na biblioteca padrão. O advisory `GO-2026-6809` identificou cadeias com intermediários comprometidos ainda aceitas por `crypto/x509`; a correção foi publicada em Go 1.26.10 e 1.27.3. Binários Go já compilados precisam ser reconstruídos para incorporar a correção da stdlib.

## Decisão

- O mínimo suportado passa a ser Go 1.26.10.
- O toolchain preferido passa a ser Go 1.27.3.
- A versão preferida e o mínimo devem ser revistos quando surgirem avisos de segurança na stdlib ou quando as versões suportadas do Go mudarem.
- Não desabilitar verificação de certificados como mitigação; atualizar o toolchain e reconstruir o binário.

## Consequências

- `go.mod` declara `go 1.26.10` e `toolchain go1.27.3`.
- `govulncheck` é executado com o toolchain selecionado; findings de módulos não alcançáveis continuam registrados, sem confundi-los com findings alcançáveis.
- O baseline de build não implica suporte de servidor fora de Linux amd64/arm64 nem prova a segurança dos stores de certificados externos ao Go.

## Referências

- [GO-2026-6809](https://pkg.go.dev/vuln/GO-2026-6809)
- [Go 1.27.3 release notes](https://go.dev/doc/devel/release#go1.27.3)
- [Go 1.26.10 release notes](https://go.dev/doc/devel/release#go1.26.10)
