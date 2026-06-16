# Padrões de Identificação de Fraude: Débitos Veiculares

## 1. Padrões de Domínio Suspeito

### 1a. Abuso de TLD de país como sigla de estado brasileiro (CRÍTICO)
Fraudadores registram domínios usando TLDs de países cujas siglas coincidem com estados BR:
- `.sc` (Seychelles) → imita Santa Catarina: ex: `detran.sc` em vez de `detran.sc.gov.br`
- `.mg` (Madagascar) → imita Minas Gerais: ex: `transito.mg`
- `.ba` (Bósnia) → imita Bahia: ex: `detran.ba`
- `.go` (não existe, mas monitorar `.go.com`, `.gov-go.com`)
- `.ms`, `.mt`, `.pa`, `.ro`, `.to`, `.ac`, `.rr`, `.ap` — monitorar variações
Qualquer domínio `detran.<sigla-estado>` ou `sefaz.<sigla-estado>` sem `.gov.br` é fraude.

### 1b. Domínios que imitam nomenclatura oficial
- Combinar palavras oficiais sem .gov.br: `ipva-fazenda-sp.org`, `sc-debito.com`
- Padrão `<órgão>-<estado>.<tld>`: `detran-sp.com`, `sefaz-rj.net`
- Padrão `<serviço><estado>.<tld>`: `ipvasp.com`, `debitosmg.net`
- Padrão `consulta<serviço>.<tld>`: `consultadeplaca.com`, `consultadeplaca.net`
- Nomes genéricos: `ipva-sp.com`, `detranbr.net`, `pagardebito.com`
- Domínios com hífen: `detran-online.com`, `ipva-online.net`
- Domínios registrados há menos de 1 ano

### 1c. TLDs suspeitos para serviços brasileiros
.org, .net, .info, .online, .site, .xyz, .io, .store, .click, .top
(Serviços oficiais brasileiros usam exclusivamente .gov.br ou .com.br)

## 2. Cobranças Indevidas
- Cobrar taxa de "consulta" (consulta oficial é GRATUITA no Detran/Sefaz)
- Cobrar "taxa de processamento" para emitir boleto (boleto oficial é gratuito)
- Planos de assinatura para "consultas ilimitadas"
- Cobrar para "desbloquear" informações do veículo

## 3. Imitação Visual (Phishing)
- Layout idêntico ao site do Detran ou Sefaz estadual
- Uso de logos e brasões oficiais sem autorização
- Cores e fontes que imitam portais governamentais
- URL diferente mas visual igual ao site oficial

## 4. Ausência de Elementos de Legitimidade
- Sem CNPJ visível no rodapé
- CNPJ inválido ou que não confere na Receita Federal
- Sem endereço físico da empresa
- Sem política de privacidade (LGPD)
- Sem termos de uso
- Certificado SSL ausente (HTTP em vez de HTTPS)
- Certificado SSL de domínio diferente do site

## 5. Solicitação de Dados Sensíveis Indevidos
- Pedir CPF + dados de cartão de crédito para "consulta"
- Solicitar dados bancários para verificação
- Pedir senha do Gov.br ou de outros portais
- Coletar dados além do necessário para o serviço

## 6. Sinais de Alerta Adicionais
- Reclamações no Reclame Aqui sobre não entrega do serviço
- Sem SAC ou canal de atendimento identificado
- Links de redes sociais quebrados ou inexistentes
- Erros ortográficos e gramaticais no conteúdo
- Pop-ups agressivos de "oferta por tempo limitado"
- Countdown timer falso para pressionar pagamento

## 7. Classificação de Risco
- ⚠️ Suspeito Leve: 0-2 flags identificadas - monitorar
- 🟠 Suspeito Moderado: 3-4 flags identificadas - investigar com prioridade
- 🔴 Provável Fraude: 5+ flags identificadas - reportar e bloquear

## 8. Ações Recomendadas por Classificação
### Suspeito Leve
- Manter em watchlist
- Re-avaliar em 30 dias
- Verificar reclamações no Reclame Aqui

### Suspeito Moderado  
- Notificar equipe de segurança
- Verificar registro do domínio (WHOIS)
- Verificar CNPJ na Receita Federal
- Buscar reclamações e notícias sobre o site

### Provável Fraude
- Reportar ao CERT.br (cert.br)
- Reportar ao Procon estadual
- Notificar o Detran/Sefaz imitado
- Incluir na blacklist imediatamente
- Considerar notificação ao MP/Polícia
