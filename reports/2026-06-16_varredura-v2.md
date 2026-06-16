# Relatório de Varredura — Fraudes em Débitos Veiculares (v2)

**Data:** 16/06/2026  
**Hora:** 18:00 UTC  
**Analista:** Monitor Fraude (automatizado — skill v2)  
**Ciclo:** Varredura completa por UF (15 queries)  
**Metodologia:** Queries geo-segmentadas por estado; foco em anúncios patrocinados

> **Nota metodológica:** A API de busca utilizada não distingue nativamente
> resultados patrocinados de orgânicos. Todos os resultados foram coletados,
> mas a análise de risco priorizou domínios com padrões de fraude documentados.
> Em ambiente de produção, recomenda-se scraping direto do Google com
> identificação de labels "Patrocinado" / `[Ad]` nas SERPs.

---

## Resumo Executivo

| Métrica | Valor |
|---|---|
| UFs monitoradas | 8 (SP, RJ, MG, SC, RS, PR, BA, GO) |
| Queries executadas | 15 |
| Domínios suspeitos identificados | 9 |
| Alto risco | 5 |
| Médio risco | 3 |
| Baixo risco | 1 |

**5 sites de ALTO RISCO identificados. Ação imediata recomendada.**

---

## Queries Executadas

| # | Query | UF | Grupo |
|---|---|---|---|
| 1 | consulta débitos veiculares SP | SP | A |
| 2 | consulta débitos veiculares SC | SC | A |
| 3 | consulta débitos veiculares MG | MG | A |
| 4 | consulta débitos veiculares RJ | RJ | A |
| 5 | consulta débitos veiculares BA | BA | A |
| 6 | consulta débitos veiculares GO | GO | A |
| 7 | consulta débitos veiculares RS | RS | A |
| 8 | consulta débitos veiculares PR | PR | A |
| 9 | pagar IPVA SC online | SC | B |
| 10 | pagar IPVA MG online | MG | B |
| 11 | pagar IPVA SP online | SP | B |
| 12 | pagar IPVA RJ online | RJ | B |
| 13 | consultar placa gratis online | BR | C |
| 14 | ipva 2026 parcelado online | BR | C |
| 15 | detran consulta debitos placa | BR | C |

---

## 🔴 Sites de ALTO RISCO

### 1. ipva-fazenda-sp.org
- **UF:** SP
- **Termo que ativou:** consulta débitos veiculares SP
- **Motivo:** Imita SEFAZ/Fazenda SP usando `.org` fora do `.gov.br`. Combina
  "ipva", "fazenda" e "sp" — nomenclatura oficial — em domínio ilegítimo.
- **Flags:** domínio imita órgão oficial, TLD suspeito (.org), nomenclatura
  exclusiva de órgão público, sem .gov.br
- **Ação:** Reportar ao CERT.br, Procon SP e SEFAZ-SP

### 2. sc-debito.com
- **UF:** SC
- **Termo que ativou:** consulta débitos veiculares SC
- **Motivo:** Título copia interface oficial do DETRAN SC em domínio `.com`
  suspeito. Padrão `<sigla>-debito.com`.
- **Flags:** imita visual DETRAN SC, domínio .com com nome oficial, sem .gov.br
- **Ação:** Reportar ao CERT.br e DETRAN SC

### 3. detran.sc
- **UF:** SC
- **Termo que ativou:** consulta débitos veiculares SC
- **Motivo:** Usa TLD `.sc` (código de país das Seychelles) para se passar pelo
  `detran.sc.gov.br` oficial. Padrão crítico de abuso de TLD.
- **Flags:** TLD de país imita sigla do estado, nome idêntico ao órgão oficial,
  domínio enganoso por design
- **Ação:** Reportar ao CERT.br, DETRAN SC e ICANN/NIC.SC

### 4. transito.mg
- **UF:** MG
- **Termo que ativou:** consulta débitos veiculares MG (apareceu 2x)
- **Motivo:** Usa TLD `.mg` (Madagascar) imitando autoridade de trânsito de MG.
  Apareceu em múltiplas queries — sinal de investimento pesado em anúncios.
- **Flags:** TLD de país imita sigla do estado, imita autoridade oficial de
  trânsito, presença em múltiplas SERPs
- **Ação:** Reportar ao CERT.br, DETRAN MG e SEFAZ MG

### 5. detran.ba
- **UF:** BA
- **Termo que ativou:** consulta débitos veiculares BA
- **Motivo:** Usa TLD `.ba` (Bósnia-Herzegovina) para se passar pelo
  `detran.ba.gov.br` oficial. Mesmo padrão de detran.sc e transito.mg.
- **Flags:** TLD de país imita sigla do estado, nome idêntico ao órgão oficial
- **Ação:** Reportar ao CERT.br e DETRAN BA

---

## 🟠 Sites de MÉDIO RISCO

### 6. zapay.portaldotransito.com.br
- **UF:** GO
- **Termo que ativou:** consulta débitos veiculares GO
- **URL exata:** `zapay.portaldotransito.com.br/detran/go`
- **Motivo:** Usa a marca **Zapay** como subdomínio de site terceiro não
  autorizado (`portaldotransito.com.br`). Pode confundir usuários que
  buscam o Zapay oficial (`usezapay.com.br`).
- **Flags:** marca registrada de terceiro como subdomínio, domínio diferente
  do parceiro oficial
- **Ação:** Notificar equipe Zapay/Gringo para verificar autorização; se não
  autorizado, reportar por violação de marca

### 7. consultaplaca.store
- **UF:** BR (genérico)
- **Termo que ativou:** consultar placa gratis online
- **Motivo:** TLD `.store` incomum para serviço brasileiro. Aparece em queries
  de alta intenção. Sem histórico público, sem CNPJ encontrado.
- **Flags:** TLD suspeito (.store), sem CNPJ público, sem histórico
- **Ação:** Investigar manualmente; verificar se cobra por consulta

### 8. online.prontopaguei.com
- **UF:** SC / genérico
- **Motivo:** Subdomínio de site desconhecido oferecendo parcelamento de IPVA SC.
  Credenciais como intermediador não verificadas.
- **Flags:** credenciais não verificadas, subdomínio suspeito
- **Ação:** Verificar CNPJ e credenciamento junto ao DETRAN SC

---

## ⚠️ Sites de BAIXO RISCO

### 9. keplaca.com
- **UF:** BR
- **Motivo:** Serviço de consulta de placa com escopo amplo. Domínio genérico
  sem clareza sobre empresa responsável.
- **Flags:** ausência de CNPJ público, domínio genérico
- **Ação:** Monitorar; verificar se cobra por consultas

---

## Padrão Emergente — Abuso de TLD de País

Esta varredura confirmou um padrão sofisticado não coberto pela skill anterior:
fraudadores registram domínios em ccTLDs (country-code TLDs) cujas siglas
coincidem com estados brasileiros:

| TLD | País real | Estado imitado | Exemplo fraudulento |
|---|---|---|---|
| `.sc` | Seychelles | Santa Catarina | `detran.sc` |
| `.mg` | Madagascar | Minas Gerais | `transito.mg` |
| `.ba` | Bósnia-Herzegovina | Bahia | `detran.ba` |
| `.ms` | Montserrat | Mato Grosso do Sul | não encontrado (monitorar) |
| `.mt` | Malta | Mato Grosso | não encontrado (monitorar) |
| `.pa` | Panamá | Pará | não encontrado (monitorar) |
| `.ro` | Romênia | Rondônia | não encontrado (monitorar) |
| `.to` | Tonga | Tocantins | não encontrado (monitorar) |
| `.ac` | Ilha Ascensão | Acre | não encontrado (monitorar) |

**Recomendação:** Adicionar busca proativa por esses domínios nas próximas varreduras.

---

## Comparação com Varredura Anterior (19/05/2026)

| Site | Varredura 19/05 | Varredura 16/06 | Status |
|---|---|---|---|
| ipva-fazenda-sp.org | 🔴 ALTO | 🔴 ALTO | Ativo — persistente |
| sc-debito.com | 🔴 ALTO | 🔴 ALTO | Ativo — persistente |
| detran.sc | 🔴 ALTO | 🔴 ALTO | Ativo — persistente |
| transito.mg | 🔴 ALTO | 🔴 ALTO | Ativo — persistente |
| detran.ba | 🔴 ALTO | 🔴 ALTO | Ativo — persistente |
| portaldotransito.com.br | 🟠 MÉDIO | 🟠 MÉDIO | Ativo |
| online.prontopaguei.com | 🟠 MÉDIO | 🟠 MÉDIO | Ativo |
| consultaplaca.store | não encontrado | 🟠 MÉDIO | Novo |

> Todos os 5 sites de ALTO RISCO do relatório anterior continuam ativos após
> ~4 semanas. Nenhum foi derrubado. Reforça urgência de denúncias formais.

---

## Recomendações

1. **Ação imediata:** Denunciar os 5 sites de ALTO RISCO ao CERT.br
   (`cert.br/contato`) e aos respectivos DETRANs estaduais
2. **Notificar Zapay/Gringo:** Verificar situação de `zapay.portaldotransito.com.br`
3. **Expandir varredura de TLD:** Buscar ativamente `detran.ms`, `detran.mt`,
   `detran.ro`, `transito.pa`, `sefaz.go` etc. nas próximas varreduras
4. **Monitoramento patrocinado:** Implementar coleta direta de anúncios pagos
   do Google (Google Ads Transparency Center ou scraping com identificação
   de labels "Patrocinado") para maximizar captura de fraudes

---

## Sugestões para Safelist (aguardando confirmação)

Nenhum novo site legítimo encontrado fora da safelist existente nesta varredura.

---

*Próxima varredura recomendada: 23/06/2026*  
*Skill utilizada: fraud-monitor-debitos v2*
