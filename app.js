import { demoEvents, detectFindings, filterEvents, normalizeEvent, parseLogText, summarize, timelineBuckets } from './core.js'

const storageKey = 'signal-desk:triage:v1'
const state = {
  events: demoEvents.map(normalizeEvent),
  findings: [],
  decisions: loadDecisions(),
  activeFinding: null,
}

const elements = Object.fromEntries([
  'fileInput', 'chooseFileButton', 'demoButton', 'exportButton', 'loadStatus', 'eventMetric', 'sourceMetric',
  'criticalMetric', 'actorMetric', 'timeline', 'findingList', 'findingCount', 'visibleCount',
  'filterForm', 'searchInput', 'sourceFilter', 'severityFilter', 'eventRows', 'emptyState',
  'findingDialog', 'dialogSeverity', 'dialogTitle', 'dialogRationale', 'dialogRecommendation',
  'dialogEvents', 'findingNote', 'saveDecisionButton',
].map((id) => [id, document.getElementById(id)]))

function loadDecisions() {
  try { return JSON.parse(localStorage.getItem(storageKey)) || {} } catch { return {} }
}

function saveDecisions() {
  try { localStorage.setItem(storageKey, JSON.stringify(state.decisions)) } catch { /* The app still works without storage. */ }
}

function resetCase(events, message, clearDecisions = false) {
  if (clearDecisions) {
    state.decisions = {}
    saveDecisions()
  }
  state.events = events.map(normalizeEvent).filter((event) => event.timestamp)
    .sort((a, b) => a.timestamp.localeCompare(b.timestamp))
  state.findings = detectFindings(state.events)
  state.activeFinding = null
  elements.searchInput.value = ''
  elements.sourceFilter.value = ''
  elements.severityFilter.value = ''
  populateSourceFilter()
  render()
  elements.loadStatus.textContent = message
}

function populateSourceFilter() {
  const selected = elements.sourceFilter.value
  const sources = [...new Set(state.events.map((event) => event.source))].sort()
  elements.sourceFilter.replaceChildren(new Option('All sources', ''), ...sources.map((source) => new Option(source, source)))
  if (sources.includes(selected)) elements.sourceFilter.value = selected
}

function render() {
  const metrics = summarize(state.events, state.findings)
  elements.eventMetric.textContent = metrics.events
  elements.sourceMetric.textContent = metrics.sources
  elements.criticalMetric.textContent = metrics.critical
  elements.actorMetric.textContent = metrics.suspiciousActors
  renderTimeline()
  renderFindings()
  renderEvents()
}

function renderTimeline() {
  const buckets = timelineBuckets(state.events)
  const maximum = Math.max(1, ...buckets.map((bucket) => bucket.total))
  elements.timeline.replaceChildren(...buckets.map((bucket) => {
    const column = document.createElement('div')
    column.className = 'timeline-column'
    const bar = document.createElement('span')
    bar.className = 'timeline-bar'
    bar.style.height = `${Math.max(7, (bucket.total / maximum) * 100)}%`
    const elevated = document.createElement('i')
    elevated.style.height = `${bucket.total ? (bucket.elevated / bucket.total) * 100 : 0}%`
    bar.append(elevated)
    const time = document.createElement('small')
    time.textContent = bucket.start.toLocaleTimeString([], { hour: 'numeric', minute: '2-digit' })
    column.title = `${bucket.total} events, ${bucket.elevated} elevated`
    column.append(bar, time)
    return column
  }))
}

function renderFindings() {
  elements.findingCount.textContent = state.findings.length
  if (!state.findings.length) {
    const empty = document.createElement('div')
    empty.className = 'empty-state'
    empty.textContent = 'No built-in correlation rules matched this data set.'
    elements.findingList.replaceChildren(empty)
    return
  }
  elements.findingList.replaceChildren(...state.findings.map((item, index) => {
    const button = document.createElement('button')
    button.type = 'button'
    button.className = 'finding-card'
    const decision = state.decisions[item.id]?.decision || 'new'
    button.innerHTML = `<span class="finding-index">${String(index + 1).padStart(2, '0')}</span><span class="severity ${item.severity}">${item.severity}</span><strong></strong><p></p><span class="finding-meta"></span>`
    button.querySelector('strong').textContent = item.title
    button.querySelector('p').textContent = item.rationale
    button.querySelector('.finding-meta').textContent = `${item.eventIds.length} linked events · ${decision}`
    button.addEventListener('click', () => openFinding(item))
    return button
  }))
}

function currentFilters() {
  return { query: elements.searchInput.value, source: elements.sourceFilter.value, severity: elements.severityFilter.value }
}

function renderEvents() {
  const events = filterEvents(state.events, currentFilters())
  elements.visibleCount.textContent = `${events.length} / ${state.events.length}`
  elements.emptyState.hidden = events.length > 0
  elements.eventRows.replaceChildren(...events.map((event) => {
    const row = document.createElement('tr')
    row.tabIndex = 0
    row.innerHTML = '<td><time></time></td><td><strong></strong><small></small></td><td><span class="event-type"></span><p></p></td><td><code></code></td>'
    const time = row.querySelector('time')
    time.dateTime = event.timestamp
    time.textContent = new Date(event.timestamp).toLocaleTimeString([], { hour: '2-digit', minute: '2-digit', second: '2-digit' })
    row.querySelector('td:nth-child(2) strong').textContent = event.source
    row.querySelector('td:nth-child(2) small').textContent = event.actor
    row.querySelector('.event-type').textContent = `${event.eventType} · ${event.outcome}`
    row.querySelector('p').textContent = event.message
    row.querySelector('code').textContent = event.ip
    return row
  }))
}

function openFinding(item) {
  state.activeFinding = item
  const saved = state.decisions[item.id] || { decision: 'new', note: '' }
  elements.dialogSeverity.textContent = `${item.severity} severity · ${item.ruleId}`
  elements.dialogTitle.textContent = item.title
  elements.dialogRationale.textContent = item.rationale
  elements.dialogRecommendation.textContent = item.recommendation
  elements.findingNote.value = saved.note || ''
  const radio = elements.findingDialog.querySelector(`input[name="decision"][value="${saved.decision}"]`)
  if (radio) radio.checked = true
  elements.dialogEvents.replaceChildren(...item.eventIds.map((id) => {
    const event = state.events.find((candidate) => candidate.id === id)
    const entry = document.createElement('div')
    if (!event) return entry
    const title = document.createElement('strong')
    title.textContent = `${new Date(event.timestamp).toLocaleTimeString()} · ${event.source}`
    const detail = document.createElement('p')
    detail.textContent = `${event.actor} — ${event.message}`
    entry.append(title, detail)
    return entry
  }))
  elements.findingDialog.showModal()
}

function saveActiveDecision() {
  if (!state.activeFinding) return
  const selected = elements.findingDialog.querySelector('input[name="decision"]:checked')
  state.decisions[state.activeFinding.id] = {
    decision: selected?.value || 'new',
    note: elements.findingNote.value.trim(),
    updatedAt: new Date().toISOString(),
  }
  saveDecisions()
  renderFindings()
}

function downloadCase() {
  const payload = {
    exportedAt: new Date().toISOString(),
    sourceNotice: 'Generated locally in Signal Desk. Validate heuristic findings before operational use.',
    summary: summarize(state.events, state.findings),
    findings: state.findings.map((item) => ({ ...item, triage: state.decisions[item.id] || { decision: 'new', note: '' } })),
    events: state.events.map(({ raw, ...event }) => event),
  }
  const url = URL.createObjectURL(new Blob([JSON.stringify(payload, null, 2)], { type: 'application/json' }))
  const link = document.createElement('a')
  link.href = url
  link.download = `signal-desk-case-${new Date().toISOString().slice(0, 10)}.json`
  link.click()
  URL.revokeObjectURL(url)
}

elements.chooseFileButton.addEventListener('click', () => elements.fileInput.click())
elements.fileInput.addEventListener('change', async () => {
  const file = elements.fileInput.files?.[0]
  if (!file) return
  if (file.size > 5 * 1024 * 1024) {
    elements.loadStatus.textContent = 'Choose a file smaller than 5 MB for this browser-based demo.'
    return
  }
  try {
    const events = parseLogText(await file.text())
    resetCase(events, `${events.length} events loaded from ${file.name}.`, true)
  } catch (error) {
    elements.loadStatus.textContent = error.message
  } finally {
    elements.fileInput.value = ''
  }
})
elements.demoButton.addEventListener('click', () => resetCase(demoEvents, 'Demo case and triage decisions reset.', true))
elements.exportButton.addEventListener('click', downloadCase)
elements.filterForm.addEventListener('input', renderEvents)
elements.saveDecisionButton.addEventListener('click', saveActiveDecision)

resetCase(demoEvents, 'Demo case loaded.')
