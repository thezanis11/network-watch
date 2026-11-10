"""Incident-oriented standalone report with imbalance-aware benchmark figures."""
import base64
import html
import json
import os
from pathlib import Path

os.environ.setdefault('MPLCONFIGDIR', str(Path(__file__).resolve().parents[1]/'.cache/matplotlib'))
import matplotlib
matplotlib.use('Agg')
import matplotlib.pyplot as plt
import numpy as np
import pandas as pd
from sklearn.metrics import confusion_matrix, precision_recall_curve


def percent(v):
    return '—' if v is None else f'{100*v:.2f} %'


def embed(path):
    return '<img alt="Mesure expérimentale" src="data:image/png;base64,'+base64.b64encode(path.read_bytes()).decode()+'">'


def build_report(manifest, prediction, traces, incidents, out):
    figures = out/'figures'
    figures.mkdir(exist_ok=True)
    results = manifest['results']
    champion = next(r for r in results if r['model'] == manifest['champion'])
    y = prediction.label.to_numpy()
    fig, axes = plt.subplots(1, 2, figsize=(12, 4.6), layout='constrained')
    colors = ['#328baf', '#b191cf', '#28ad91', '#ecab67', '#667b94', '#9d9d9d', '#d85464']
    for i, r in enumerate(results):
        if r['model'] == 'Always benign':
            continue
        precision, recall, _ = precision_recall_curve(y, traces[r['model']])
        axes[0].plot(recall, precision, label=f'{r["model"]} · AP {r["test"]["average_precision"]:.3f}', color=colors[i % len(colors)], lw=1.6)
    axes[0].axhline(y.mean(), ls='--', color='#c44c5f', label=f'Prévalence {y.mean():.1%}')
    axes[0].set(xlabel='Rappel', ylabel='Précision', xlim=(0, 1), ylim=(0, 1.02), title='Un F1 élevé peut être trivial si presque tout est malveillant')
    axes[0].legend(fontsize=7, loc='lower left')
    alert = traces[champion['model']] > champion['threshold']
    counts = confusion_matrix(y, alert, labels=[0, 1])
    normalized = counts/np.maximum(counts.sum(axis=1, keepdims=True), 1)
    axes[1].imshow(normalized, vmin=0, vmax=1, cmap='Blues')
    axes[1].set(xticks=[0, 1], xticklabels=['Normal prédit', 'Alerte prédite'], yticks=[0, 1],
                yticklabels=['Bénin connu', 'Malveillant connu'], title=f'Modèle choisi en validation · {champion["model"]}')
    for i in range(2):
        for j in range(2):
            axes[1].text(j, i, f'{counts[i,j]:,}\n{normalized[i,j]:.1%}', ha='center', va='center', color='white' if normalized[i,j] > .6 else '#172132')
    fig.savefig(figures/'benchmark.png', dpi=160)
    plt.close(fig)
    captures = sorted(champion['by_capture'])
    fig, axes = plt.subplots(1, 2, figsize=(12, 4), layout='constrained')
    labels = [c.removeprefix('ctu-idseval-6-').replace('-', '\n') for c in captures]
    recalls = [champion['by_capture'][c]['recall'] if champion['by_capture'][c]['attacks'] else np.nan for c in captures]
    fprs = [champion['by_capture'][c]['false_positive_rate'] for c in captures]
    axes[0].bar(np.arange(len(captures)), recalls, color='#28ad91')
    axes[1].bar(np.arange(len(captures)), [np.nan if v is None else v for v in fprs], color='#ecab67')
    for ax in axes:
        ax.set(xticks=np.arange(len(captures)), xticklabels=labels, ylim=(0, 1.05))
    axes[0].set(ylabel='Rappel sur attaques', title='Ne pas masquer le malware par le volume du scan')
    axes[1].set(ylabel='Taux de faux positifs', title='Absence de barre = aucune trame bénigne annotée')
    fig.savefig(figures/'capture_breakdown.png', dpi=160)
    plt.close(fig)
    rows = ''
    for r in results:
        m = r['test']
        rows += f'<tr><td>{r["model"]}</td><td>{percent(m["precision"])}</td><td>{percent(m["recall"])}</td><td>{m["f1"]:.3f}</td><td>{percent(m["balanced_accuracy"])}</td><td>{m["mcc"]:.3f}</td><td>{percent(m["false_positive_rate"])}</td></tr>'
    detail_rows = ''
    for capture, m in champion['by_capture'].items():
        detail_rows += f'<tr><td>{capture}</td><td>{m["flows"]:,}</td><td>{m["attacks"]:,}</td><td>{percent(m["recall"]) if m["attacks"] else "—"}</td><td>{m["false_positive_flows"]}</td><td>{percent(m["false_positive_rate"])}</td></tr>'
    incident_rows = ''
    if len(incidents):
        for item in incidents.sort_values(['max_score', 'alert_flows'], ascending=False).head(100).to_dict('records'):
            search = html.escape(f'{item["capture"]} {item["host"]} {item["reason"]} {item["retrospective_status"]}')
            incident_rows += (f'<tr data-search="{search}"><td>{item["host"]}</td><td>{html.escape(item["reason"])}</td>'
                              f'<td>{item["alert_flows"]}</td><td>{item["last_seen"]-item["first_seen"]:.1f} s</td>'
                              f'<td>{html.escape(item["retrospective_status"])}</td></tr>')
    inventory_rows = ''.join(f'<tr><td>{i["capture"]}</td><td>{i["split"]}</td><td>{i["benign"]:,}</td><td>{i["malicious"]:,}</td><td>{i["unknown"]:,}</td></tr>' for i in manifest['inventory'])
    low_rows = ''.join(f'<tr><td>{r["model"]}</td><td>{percent(r["low_fpr"]["validation"]["false_positive_rate"])}</td><td>{percent(r["low_fpr"]["test"]["recall"])}</td><td>{percent(r["low_fpr"]["test"]["false_positive_rate"])}</td></tr>' for r in results if 'low_fpr' in r)
    benign_count = int((y == 0).sum())
    document = '''<!doctype html><html lang="fr"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1"><title>Network Watch — analyse réseau et incidents</title><style>
*{box-sizing:border-box}body{margin:0;background:#0b1420;color:#eef4fa;font:16px/1.65 system-ui}main{max-width:1200px;margin:auto;padding:44px 24px}h1{font-size:clamp(40px,6vw,72px);line-height:1.05;letter-spacing:-.05em}h2{font-size:26px}p,li{color:#b5c5d8}.eyebrow{color:#6ab9ff;text-transform:uppercase;letter-spacing:.15em;font-size:12px}.cards{display:grid;grid-template-columns:repeat(4,1fr);gap:14px}.card,section{background:#142337;border:1px solid #2b4159;border-radius:13px;padding:22px;margin:22px 0}.card b{display:block;color:#6ab9ff;font-size:30px}.card span{color:#b5c5d8;font-size:13px}.notice{border-left:3px solid #ffc07d;background:#2a2634;padding:16px;margin:24px 0}img{width:100%;border-radius:8px}.scroll{overflow:auto}table{width:100%;border-collapse:collapse;font-size:12px;white-space:nowrap}td,th{padding:12px;text-align:left;border-bottom:1px solid #30465e}input{background:#0b1420;color:#eef4fa;padding:12px;border:1px solid #486582;border-radius:7px;width:100%;max-width:600px;margin:10px 0 20px}a{color:#6ab9ff}@media(max-width:700px){.cards{grid-template-columns:repeat(2,1fr)}main{padding:24px 12px}section{padding:15px}}
</style></head><body><main><div class="eyebrow">Network Watch · détection & investigation</div><h1>Des flux réseau<br>aux incidents explicables.</h1><p>Chaîne hors ligne de lecture Zeek et Suricata EVE, caractéristiques causales, détecteurs statistiques et supervisés, puis corrélation des alertes. Les expériences utilisent les journaux annotés réels CTU-IDSEVAL-6.</p>
<div class="cards"><div class="card"><b>OBSERVED</b><span>flux traités après purge</span></div><div class="card"><b>FEATURES</b><span>caractéristiques sans IP ni date absolue</span></div><div class="card"><b>INCIDENTS</b><span>groupes d'alertes au test</span></div><div class="card"><b>EPISODES</b><span>rappel des épisodes de référence</span></div></div>
<div class="notice">Étude exploratoire sur six captures. Le test comporte PREVALENCE de flux malveillants parmi les labels connus : le F1 seul peut être trompeur. Les flux Background restent inconnus et ne sont jamais transformés en trafic bénin.</div>
<section><div class="eyebrow">01 / Benchmark</div><h2>Comparer aussi aux prédictions triviales</h2><p>Modèle retenu : <b>CHAMPION</b>, choisi uniquement sur le F1 de validation. Le test contient BENIGN_COUNT flux bénins annotés. Balanced accuracy et MCC complètent précision, rappel et F1.</p><div class="scroll"><table><tr><th>Méthode</th><th>Précision</th><th>Rappel</th><th>F1</th><th>Balanced accuracy</th><th>MCC</th><th>Fausses alertes</th></tr>ROWS</table></div>BENCHMARK_IMAGE
<h2>Réglage alternatif : au plus 1 % de fausses alertes en validation</h2><p>Cette contrainte empirique ne garantit pas le même taux au test. Les seuils équilibrés des modèles non supervisés utilisent les labels de validation ; leur ajustement statistique utilise seulement le trafic bénin.</p><div class="scroll"><table><tr><th>Modèle</th><th>Faux positifs validation</th><th>Rappel test</th><th>Faux positifs test</th></tr>LOW_ROWS</table></div></section>
<section><div class="eyebrow">02 / Généralisation</div><h2>Conserver le détail par capture</h2>CAPTURE_IMAGE<div class="scroll"><table><tr><th>Capture</th><th>Flux connus</th><th>Attaques</th><th>Rappel</th><th>Faux positifs</th><th>Taux</th></tr>DETAIL_ROWS</table></div><p>Un seul malware et un grand scan sont gardés au test : ces volumes ne constituent pas des milliers d'expériences indépendantes. Aucun intervalle de confiance obtenu par mélange aléatoire de flux corrélés n'est revendiqué.</p></section>
<section><div class="eyebrow">03 / Triage</div><h2>Des alertes aux incidents corrélés</h2><p>Regroupement par capture, hôte source et motif, tant que l'écart entre alertes n'excède pas 120 s. Les labels ne servent pas au regroupement. Les statuts affichés ci-dessous sont ajoutés rétrospectivement pour l'évaluation. Les hôtes sont représentés par des pseudonymes déterministes.</p><label for="filter">Filtrer les 100 premiers incidents affichés</label><input id="filter" type="search" placeholder="Motif, hôte, statut…"><div class="scroll"><table><tr><th>Hôte</th><th>Motif</th><th>Alertes</th><th>Durée</th><th>Statut rétrospectif</th></tr>INCIDENT_ROWS</table></div><p><a href="incidents.csv">Tous les incidents en CSV</a> · <a href="reference_episodes.json">Épisodes de référence</a> · <a href="experiment.json">Manifeste d'expérience</a></p><p>Les épisodes de référence sont dérivés des flux malveillants d'un même hôte et comportement, séparés par plus de 300 s. Ils ne remplacent pas des incidents annotés par un expert. Le délai mesuré part de la première disponibilité d'un flux, pas du premier paquet de l'attaque.</p></section>
<section><div class="eyebrow">04 / Traçabilité</div><h2>Lots et labels</h2><div class="scroll"><table><tr><th>Capture</th><th>Lot</th><th>Bénin</th><th>Malveillant</th><th>Inconnu</th></tr>INVENTORY_ROWS</table></div><ul><li>Malware-1 et portscan-1 à l'entraînement ; portscan-2 à la validation ; malware-2 et portscan-3 au test.</li><li>La seule capture utilisateur est découpée chronologiquement en 60/20/20, avec purges de 300 s de part et d'autre des bornes. L'historique est réinitialisé à chaque partition.</li><li>La disponibilité d'un flux est approximée par début + durée. Les statistiques d'une connexion ne sont pas traitées comme connues dès son premier paquet.</li><li>Les caractéristiques utilisent le flux terminé courant et les observations antérieures : volumes, asymétries, états, protocoles, diversité des destinations et ports, périodicité. Les labels, noms de capture, IP, UID et temps absolus sont exclus du modèle.</li><li>Le modèle sans historique mesure la contribution des fenêtres et de la périodicité. Une amélioration n'est pas supposée à l'avance.</li><li>Les fichiers originaux téléchargés sont contrôlés par checksum. Les flux inconnus participent à l'historique mais sont exclus des métriques binaires.</li></ul></section>
<section><h2>Limites et usage</h2><p>Ce prototype n'est pas un SOC déployé ni une protection validée en production. Les scores des modèles ne sont pas des probabilités calibrées d'incident. L'adaptateur EVE est vérifié sur des fixtures ; aucune performance Suricata en production n'est mesurée ici. Les événements d'alerte EVE et de fin de flux peuvent être deux vues d'une même connexion : les fournir ensemble n'est pas une déduplication complète de flux.</p><p>Dataset : <a href="https://zenodo.org/records/21027042">CTU-IDSEVAL-6 · Stratosphere Laboratory · CC BY 4.0</a>. Schéma : <a href="https://docs.suricata.io/en/latest/output/eve/eve-json-output.html">Suricata EVE JSON</a>.</p></section></main><script>document.getElementById('filter').oninput=function(){const q=this.value.toLowerCase();document.querySelectorAll('[data-search]').forEach(row=>row.hidden=!row.dataset.search.toLowerCase().includes(q));};</script></body></html>'''
    substitutions = dict(OBSERVED=f'{manifest["observed_flows"]:,}', FEATURES=str(manifest['features']), INCIDENTS=str(manifest['incidents']),
                         EPISODES=percent(manifest['episode_recall']), PREVALENCE=percent(float(y.mean())), CHAMPION=manifest['champion'],
                         BENIGN_COUNT=str(benign_count), ROWS=rows, LOW_ROWS=low_rows, DETAIL_ROWS=detail_rows,
                         INCIDENT_ROWS=incident_rows, INVENTORY_ROWS=inventory_rows,
                         BENCHMARK_IMAGE=embed(figures/'benchmark.png'), CAPTURE_IMAGE=embed(figures/'capture_breakdown.png'))
    for key in sorted(substitutions, key=len, reverse=True):
        document = document.replace(key, substitutions[key])
    (out/'index.html').write_text(document, encoding='utf-8')
    lines = ['# Network Watch — résultats', '', f'Modèle choisi en validation : **{manifest["champion"]}**.', '',
             '| Méthode | F1 | Rappel | Balanced accuracy | Faux positifs |', '|---|---:|---:|---:|---:|']
    for r in results:
        m = r['test']
        lines.append(f'| {r["model"]} | {m["f1"]:.3f} | {percent(m["recall"])} | {percent(m["balanced_accuracy"])} | {percent(m["false_positive_rate"])} |')
    lines += ['', f'Prévalence des attaques parmi les labels de test connus : {y.mean():.2%}.',
              'Consulter le rapport pour les scores par capture et les limites ; les flux inconnus sont exclus des métriques binaires.']
    (out/'RESULTS_FR.md').write_text('\n'.join(lines)+'\n', encoding='utf-8')
