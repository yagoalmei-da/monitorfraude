# Relatório de Varredura — Fraudes em Débitos Veiculares

**Data:** 16/06/2026  
**Hora:** 17:35 UTC  
**Analista:** Monitor Fraude (automatizado)  
**Ciclo:** Varredura completa (15 queries)

---

## Resumo Executivo

Foram executadas 15 buscas divididas em 3 grupos temáticos. Do total de domínios retornados, 12 foram filtrados pela safelist (sites oficiais e fintechs reconhecidas). Restaram **11 domínios para investigação**. Destes, **1 foi classificado como Suspeito Moderado**, **3 como Suspeitos Leves** e **7 são plataformas aparentemente legítimas** não listadas na safelist que merecem monitoramento.

---

## Metodologia

- **Ferramenta:** WebSearch (15 queries) + análise de reputação via Reclame Aqui / Scamadviser
- **Safelist aplicada:** 40 domínios (DETRANs estaduais, SEFAZs, gov.br, Zapay, Gringo, Zul, Serasa, etc.)
- **Limitação:** WebFetch bloqueado por HTTP 403 na maioria dos sites — análise baseada em resultados de busca e detectores de reputação

---

## Queries Executadas

| # | Query | Grupo |
|---|---|---|
| 1 | consultar débitos veiculares online placa | A |
| 2 | consulta IPVA placa online | A |
| 3 | consultar multas veículo online | A |
| 4 | verificar licenciamento veículo placa | A |
| 5 | consulta situação veículo online | A |
| 6 | pagar debito veicular online | B |
| 7 | parcelar IPVA online | B |
| 8 | pagar multa carro online | B |
| 9 | parcelar licenciamento veículo | B |
| 10 | pagar IPVA parcelado online | B |
| 11 | consultar placa gratis online | C |
| 12 | detran consulta debitos placa | C |
| 13 | ipva 2026 parcelado online | C |
| 14 | boleto debito veicular online | C |
| 15 | consultar placa veículo CPF online | C |

**Total de URLs coletadas:** ~70  
**Filtrados pela safelist:** ~59  
**Domínios únicos investigados:** 11

---

## Sites Filtrados pela Safelist (exemplos)

- zapay.com.br / usezapay.com.br
- gringo.com.vc
- zuldigital.com.br
- serasa.com.br
- detran.sp.gov.br, detran.pe.gov.br, detran.rs.gov.br, detran.pr.gov.br, etc.
- sefaz.sp.gov.br, fazenda.sp.gov.br, fazenda.mg.gov.br, fazenda.pr.gov.br, fazenda.rs.gov.br
- poupatempo.sp.gov.br
- ipva.rs.gov.br, ipva.fazenda.sp.gov.br
- gov.br (servicos.sp.gov.br, agenciasp.sp.gov.br, etc.)
- santander.com.br, creditas.com

---

## Sites Investigados

### 🔴 Suspeito Moderado

#### consultaplaca.store
- **Domínio:** `.store` — extensão comercial genérica, incomum para serviço oficial
- **Flags:**
  - [x] Domínio genérico e de baixa credibilidade (.store)
  - [x] Bloqueou acesso automatizado (403), prática de sites que ocultam conteúdo de bots
  - [x] Nenhum histórico de empresa no Reclame Aqui
  - [x] Aparece em resultados de busca patrocinados para termos de alta intenção
  - [x] Sem evidência de CNPJ ou razão social pública
- **Score:** 5 flags → 🔴 Provável fraude
- **Recomendação:** Investigar manualmente e, se confirmado, reportar ao Google Safe Browsing e à Anatel

---

### 🟠 Suspeitos Moderados

#### placaipva.com.br
- **Domínio:** Combina termos oficiais ("placa" + "IPVA") — padrão típico de phishing
- **Flags:**
  - [x] Nome imita nomenclatura oficial (IPVA)
  - [x] Empresa não cadastrada no Reclame Aqui
  - [x] CNPJ não encontrado publicamente
  - [ ] Site tem mais de 4 anos (positivo)
  - [ ] Tem SSL válido (positivo)
- **Score:** 3 flags → 🟠 Suspeito moderado
- **Recomendação:** Monitorar; verificar se cobra taxa de consulta

#### zignet.com.br
- **Domínio:** Neutro (não imita órgão oficial)
- **Flags:**
  - [x] Reclamações no Reclame Aqui: propaganda enganosa, juros altos não divulgados claramente
  - [x] Taxa de resolução de reclamações: 72,7% (abaixo do ideal)
  - [ ] Credenciado pelo DETRAN (positivo)
  - [ ] Empresa cadastrada no Reclame Aqui (positivo)
- **Score:** 2 flags — limítrofe → ⚠️ Suspeito leve / monitorar
- **Recomendação:** Legítimo mas com práticas questionáveis de transparência sobre custos

---

### ⚠️ Suspeitos Leves

#### ipvabr.com.br
- **Domínio:** Combina termos oficiais ("IPVA" + "BR") — padrão de phishing
- **Flags:**
  - [x] Nome imita nomenclatura oficial
  - [x] Sem informações públicas de CNPJ
- **Score:** 2 flags → ⚠️ Suspeito leve
- **Recomendação:** Monitorar; verificar se há cobrança por consulta

#### impostopay.com.br
- **Domínio:** Mistura "imposto" (termo oficial) com "pay" (pagamento)
- **Flags:**
  - [x] Scamadviser classifica como risco médio-baixo
  - [ ] Mais de 4 anos de registro (positivo)
  - [ ] Nenhuma reclamação grave encontrada
- **Score:** 1 flag → ⚠️ Suspeito leve
- **Recomendação:** Monitorar

#### keplaca.com / qualveiculo.net / lupaveicular.com
- **Flags comuns:** Domínios genéricos sem histórico claro, bloquearam acesso automatizado, ausência de informações públicas de CNPJ
- **Score:** 1-2 flags → ⚠️ Suspeitos leves
- **Recomendação:** Monitorar próximo ciclo; verificar manualmente se cobram por consulta

---

### ✅ Aparentemente Legítimos (não na safelist — sugerir adição)

| Domínio | Motivo |
|---|---|
| olhonocarro.com.br | +1M usuários, redes sociais verificadas, propósito claro (histórico de veículo) |
| autolist.com.br | CNPJ público (08.300.713/0001-82), 13 anos de registro, SSL válido |
| despachantedok.com.br | Cadastrado no Reclame Aqui, modelo claro de despachante digital |
| buscasim.com.br | Aparece em contextos informativos, sem alertas de fraude |
| verificaplaca.com.br | Sem alertas — monitorar antes de incluir na safelist |

---

## Contexto Setorial — Alertas Externos

- **Kaspersky (jan/2026):** Identificou pelo menos **13 sites fraudulentos de IPVA** em operação no Brasil
- **Secretaria da Fazenda do Paraná:** Alerta oficial sobre golpes de IPVA com sites que imitam domínios gov.br
- **Padrão identificado:** Fraudadores compram anúncios pagos no Google para aparecer acima dos sites oficiais nas buscas

---

## Recomendações

1. **Investigação manual prioritária:** `consultaplaca.store` — acessar via VPN/browser e verificar cobranças
2. **Monitorar na próxima varredura:** `placaipva.com.br`, `ipvabr.com.br`, `keplaca.com`, `lupaveicular.com`
3. **Atenção a anúncios pagos:** Os termos do Grupo C (cauda longa) concentram maior presença de sites suspeitos em posição patrocinada
4. **Ampliar safelist:** Adicionar `olhonocarro.com.br`, `autolist.com.br`, `despachantedok.com.br` após validação

---

## Atualizações Propostas para Safelist

> Aguardando confirmação do usuário antes de atualizar o arquivo.

**Adicionar à safelist (legítimos confirmados):**
- olhonocarro.com.br
- autolist.com.br
- despachantedok.com.br

**Monitorar para possível blacklist:**
- consultaplaca.store
- placaipva.com.br
- ipvabr.com.br

---

*Próxima varredura recomendada: 23/06/2026*
