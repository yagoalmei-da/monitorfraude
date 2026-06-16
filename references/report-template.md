# Relatório de Monitoramento de Fraudes - Débitos Veiculares

---

## Cabeçalho

| Campo | Valor |
|-------|-------|
| **Data** | YYYY-MM-DD |
| **Hora de Início** | HH:MM |
| **Hora de Fim** | HH:MM |
| **Analista** | [Nome do Analista] |
| **Versão** | 1.0 |

---

## Resumo Executivo

Neste ciclo de varredura foram executadas **N queries** de busca, retornando **N URLs únicas**. Após filtragem pela safelist, foram identificados **N domínios suspeitos** para investigação aprofundada.

| Classificação | Quantidade |
|---------------|------------|
| 🔴 Provável Fraude | 0 |
| 🟠 Suspeito Moderado | 0 |
| ⚠️ Suspeito Leve | 0 |
| ✅ Legítimo (safelist) | 0 |
| **Total investigado** | **0** |

---

## Metodologia

1. **Coleta**: Execução de 15 queries de busca agrupadas por tema (consulta, pagamento, variações)
2. **Filtragem**: Remoção de domínios presentes na safelist (sites .gov.br e fintechs conhecidas)
3. **Investigação**: Acesso direto aos sites suspeitos via WebFetch para análise manual
4. **Classificação**: Aplicação dos critérios definidos em suspicious-patterns.md
5. **Documentação**: Registro de evidências e geração deste relatório

---

## Queries Executadas

### Grupo A - Consulta de Débitos
| # | Query | URLs Coletadas |
|---|-------|----------------|
| 1 | "consultar débitos veiculares online placa" | N |
| 2 | "consulta IPVA placa online" | N |
| 3 | "consultar multas veículo online" | N |
| 4 | "verificar licenciamento veículo placa" | N |
| 5 | "consulta situação veículo online" | N |

### Grupo B - Pagamento de Débitos
| # | Query | URLs Coletadas |
|---|-------|----------------|
| 6 | "pagar debito veicular online" | N |
| 7 | "parcelar IPVA online" | N |
| 8 | "pagar multa carro online" | N |
| 9 | "parcelar licenciamento veículo" | N |
| 10 | "pagar IPVA parcelado online" | N |

### Grupo C - Variações e Iscas
| # | Query | URLs Coletadas |
|---|-------|----------------|
| 11 | "consultar placa gratis online" | N |
| 12 | "detran consulta debitos placa" | N |
| 13 | "ipva 2025 parcelado online" | N |
| 14 | "boleto debito veicular online" | N |
| 15 | "consultar placa veículo CPF online" | N |

---

## Sites Investigados

### [nome-do-site.com]

**URL**: https://exemplo.com  
**Data de acesso**: YYYY-MM-DD HH:MM  
**Classificação**: 🔴 / 🟠 / ⚠️

| Critério de Análise | Resultado | Flag? |
|--------------------|-----------|-------|
| Cobra taxa de consulta? | Sim/Não | ✅/🚩 |
| Imita visual oficial? | Sim/Não | ✅/🚩 |
| Tem CNPJ visível? | Sim/Não | ✅/🚩 |
| Tem política de privacidade? | Sim/Não | ✅/🚩 |
| Pede dados sensíveis indevidos? | Sim/Não | ✅/🚩 |
| SSL válido e correto? | Sim/Não | ✅/🚩 |
| Domínio .gov.br? | Sim/Não | ✅/🚩 |

**Flags identificadas**: N/7  
**Evidências**: [Descrição do que foi encontrado]  
**Ação recomendada**: [Monitorar / Investigar / Bloquear / Reportar]

---

## Tabela Consolidada de Suspeitos

| Domínio | Flags | Classificação | Ação |
|---------|-------|---------------|------|
| exemplo1.com | 6/7 | 🔴 Provável Fraude | Reportar + Bloquear |
| exemplo2.com | 4/7 | 🟠 Suspeito Moderado | Investigar |
| exemplo3.com | 1/7 | ⚠️ Suspeito Leve | Monitorar |

---

## Recomendações

1. **Imediatas**: [Ações que devem ser tomadas nas próximas 24h]
2. **Curto Prazo (7 dias)**: [Ações de acompanhamento]
3. **Médio Prazo (30 dias)**: [Melhorias no processo]

---

## Novos Sites para Safelist

| Domínio | Justificativa |
|---------|---------------|
| novo-legitimo.com.br | [Razão para inclusão] |

---

## Novos Sites para Blacklist

| Domínio | Classificação | Data Identificação | Evidências |
|---------|---------------|-------------------|------------|
| fraude1.com | 🔴 Provável Fraude | YYYY-MM-DD | [Link/Descrição] |

---

*Relatório gerado automaticamente pelo sistema MonitorFraude*  
*Próxima varredura programada: YYYY-MM-DD*
