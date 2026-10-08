# defectdojo-sync (all-in-one)

Un singur container Docker care sincronizeaza periodic vulnerabilitatile din
**Greenbone/OpenVAS** si **Wazuh** in **DefectDojo** — fiecare intr-un
Product/Engagement separat.

```
Greenbone/OpenVAS (GMP socket) ──┐
                                 ├─▶ defectdojo-sync ─▶ DefectDojo API
Wazuh 4.14 API :55000 +          ──┘      │
OpenSearch/indexer :9200                  │ scan_type: "OpenVAS Parser" / "Wazuh"
```

## Ce face

| # | Sursa | Cum extrage | Parser DefectDojo | Destinatia |
|---|-------|-------------|-------------------|------------|
| 1 | Greenbone/OpenVAS via socket `/run/gvmd/gvmd.sock` (GMP v22.7) | ultimul raport XML al fiecarui task `Done`/`Stopped` | `OpenVAS Parser` (v1) | Product `Greenbone` / Engagement `Greenbone Automated Scans` |
| 2 | Wazuh API `https://<wazuh>:55000` + OpenSearch `wazuh-states-vulnerabilities-*` | toate vulnerabilitatile agentilor (scroll paginat) | `Wazuh` (nativ v4.8) | Product `Wazuh` / Engagement `Wazuh Automated Scans` |

- **Anti-duplicat**: OpenVAS tine minte `report_id`-urile importate
  (`data/state/openvas-state.txt`); Wazuh compara un fingerprint SHA256 al
  setului de findings (`data/state/wazuh-sync-state.json`) si sare peste import
  daca nimic nu s-a schimbat. In DefectDojo, reimportul face dedup si dupa
  `unique_id_from_tool`.
- **Rulare periodica**: scheduler APScheduler la `SYNC_INTERVAL` secunde
  (default 3600). Un esec la o sursa nu opreste cealalta.
- **Chunking Wazuh**: DefectDojo refuza fisiere > 100 MB. Cu ~100k findings
  exportul are ~300 MB, deci e impartit automat in chunkuri de
  `MAX_FINDINGS_PER_IMPORT` (default 15000 ≈ 30–40 MB) importate secvential
  in acelasi test.

## Structura

```
defectdojo-sync/
├── Dockerfile              # imagine unica (gvm-tools + opensearch-py + ...)
├── requirements.txt
├── docker-compose.yml      # un singur serviciu: defectdojo-sync
├── .env                    # configuratia REALA (NU se comite in git!)
├── .env.example            # sablon
├── README.md
└── app/
    ├── common.py            # shared: DefectDojo API, logging, init storage
    ├── openvas_sync.py      # modulul openvas-*
    ├── wazuh_sync.py        # modulul wazuh-*
    └── sync.py              # orchestrator + scheduler
└── data/                   # creat la runtime (NU se comite)
    ├── openvas-reports/    # *.xml descarcate din Greenbone
    ├── wazuh-reports/      # wazuh_part_*.json
    └── state/              # openvas-state.txt, wazuh-sync-state.json
```

> Conventie de nume: directoare/rapoarte/env-uri cu `openvas-*` / `wazuh-*`.
> Modulele Python folosesc `_` (`openvas_sync.py`) pentru ca `-` nu e permis
> in `import`.

## Configurare

1. Copiaza sablonul si completeaza-l:

```bash
cp .env.example .env
```

2. Variabile (toate in **un singur `.env`**):

| Variabila | Default | Descriere |
|---|---|---|
| `DEFECTDOJO_URL` | `http://defectdojo.example.local:8080` | URL DefectDojo |
| `DEFECTDOJO_API_TOKEN` | — | token API (obligatoriu) |
| `DEFECTDOJO_VERIFY_TLS` | `false` | verifica cert TLS DefectDojo |
| `DEFECTDOJO_PRODUCT_TYPE` | `Security Scanning` | product type comun |
| `SYNC_INTERVAL` | `3600` | secunde intre rulari |
| `LOG_LEVEL` | `INFO` | nivel log |
| `GVM_SOCKET` | `/run/gvmd/gvmd.sock` | socket gvmd (montat ca volum) |
| `GVM_USERNAME` / `GVM_PASSWORD` | `admin` | creds Greenbone |
| `OPENVAS_PRODUCT` | `Greenbone` | Product DefectDojo pt. OpenVAS |
| `OPENVAS_ENGAGEMENT` | `Greenbone Automated Scans` | Engagement pt. OpenVAS |
| `OPENVAS_SCAN_TYPE` | `OpenVAS Parser` | ⚠️ nu folosi `v2` (bug DefectDojo, vezi mai jos) |
| `OPENVAS_REPORT_DIR` | `/data/openvas-reports` | rapoarte XML |
| `OPENVAS_STATE_FILE` | `/data/state/openvas-state.txt` | stare anti-duplicat |
| `OPENVAS_ONLY_FINISHED` | `true` | importa doar taskuri Done/Stopped |
| `WAZUH_BASE_URL` | `https://wazuh…:55000` | ⚠️ obligatoriu **cu portul `:55000`** (API, nu dashboard) |
| `WAZUH_USERNAME` / `WAZUH_PASSWORD` | — | user API Wazuh |
| `WAZUH_VERIFY_TLS` | `false` | verifica cert TLS Wazuh API |
| `WAZUH_GROUP` | _(gol)_ | grup Wazuh; gol = toti agentii |
| `WAZUH_AGENT_LIMIT` | `100000` | limita agenti per interogare |
| `OPENSEARCH_HOST` / `OPENSEARCH_PORT` | — | indexerul Wazuh (obligatoriu pt. Wazuh ≥ 4.8) |
| `OPENSEARCH_USERNAME` / `OPENSEARCH_PASSWORD` | — | creds indexer (ex. user read-only) |
| `OPENSEARCH_VERIFY_TLS` | `false` | verifica cert TLS indexer |
| `OPENSEARCH_INDEX` | `wazuh-states-vulnerabilities-*` | index vulnerabilitati |
| `WAZUH_MIN_SEVERITY` | _(gol)_ | ex. `Critical,High`; gol = toate |
| `WAZUH_PRODUCT` | `Wazuh` | Product DefectDojo pt. Wazuh |
| `WAZUH_ENGAGEMENT` | `Wazuh Automated Scans` | Engagement pt. Wazuh |
| `WAZUH_SCAN_TYPE` | `Wazuh` | parser nativ DefectDojo |
| `WAZUH_TEST_TITLE` | `Wazuh vulnerabilities` | titlul testului |
| `WAZUH_REPORT_DIR` | `/data/wazuh-reports` | chunkuri JSON |
| `WAZUH_STATE_FILE` | `/data/state/wazuh-sync-state.json` | stare anti-duplicat |
| `MAX_FINDINGS_PER_IMPORT` | `15000` | findings per chunk (< 100 MB) |
| `WAZUH_CLOSE_OLD_FINDINGS` | `false` | inchide findings lipsa din import; tine `false` cu import chunked |

## Rulare

```bash
cd /opt/defectdojo-sync
docker compose build
docker compose up -d

# o singura rulare (ambele surse)
docker compose run --rm defectdojo-sync python -m sync --once
# doar o sursa
docker compose run --rm defectdojo-sync python -m sync --once --only openvas
docker compose run --rm defectdojo-sync python -m sync --once --only wazuh
# inspectie
docker compose run --rm defectdojo-sync python -m sync --list-tasks
docker compose run --rm defectdojo-sync python -m sync --list-agents
# loguri
docker compose logs -f defectdojo-sync
```

## CI/CD (GitHub Actions)

La fiecare tag `v*` workflow-ul `.github/workflows/build-release.yml`:
1. construieste imaginea Docker si o publica in **GHCR**
   (`ghcr.io/<owner>/defectdojo-sync:<tag>`),
2. impacheteaza proiectul (fara `.env`/`data/`) intr-un **release zip**
   atasat la GitHub Release.

## Probleme cunoscute (rezolvate aici)

1. `AttributeError: 'GMP' object has no attribute 'authenticate'` — in
   `python-gvm ≥ 25`, `GMP` e un dispatcher si **trebuie** folosit ca
   `with GMP(...) as gmp:` (negociaza automat `GMPv227`).
2. DefectDojo `OpenVAS Parser v2` da `500` (`'NoneType' has no attribute
   'find'` / `cleanup_openvas_text(None)`): se trimite wrapper-ul XML extern
   (`report/report/results`) si se foloseste parserul v1 `OpenVAS Parser`.
3. DefectDojo refuza fisiere > 100 MB — exportul Wazuh (~100k findings) e
   impartit in chunkuri de ~30–40 MB.
4. Pe Wazuh ≥ 4.8 endpoint-ul `/vulnerability/{agent}` nu mai exista (404);
   vulnerabilitatile se citesc din OpenSearch (`wazuh-states-vulnerabilities-*`),
   deci trebuie creds de indexer, nu doar de API.
5. `Closed` umflat in DefectDojo: cu `close_old_findings=true` + import in
   chunkuri, fiecare chunk inchide findings-urile celorlalte chunkuri.
   De aceea `WAZUH_CLOSE_OLD_FINDINGS` e `false` by default — findings se
   inchid doar manual sau cand remedierea e confirmata, iar dedup-ul se face
   dupa cheie stabila (`CVE + agent_id` via `unique_id_from_tool`).

## Securitate

- `.env` contine parole reale si **nu se comite** (e in `.gitignore`).
  In git ajunge doar `.env.example`.

## Crearea utilizatorului Wazuh Manager API (`defectdojo-api`)

Sync-ul Wazuh foloseste un user API dedicat cu rol **readonly** (ID 2),
nu contul administrator `wazuh`. Comenzile de mai jos se executa pe
managerul Wazuh (API pe portul **55000**). Daca le rulezi de pe alt host,
inlocuieste `127.0.0.1` cu `wazuh.example.local`.

### 1. Ia un token ca admin

```bash
TOKEN=$(curl -sk -u 'wazuh:PAROLA_WAZUH' \
  -X POST \
  'https://127.0.0.1:55000/security/user/authenticate?raw=true')

echo "$TOKEN"
```

### 2. Verifica utilizatorii existenti

```bash
curl -sk \
  -H "Authorization: Bearer $TOKEN" \
  'https://127.0.0.1:55000/security/users?pretty=true'
```

### 3. Daca utilizatorul nu exista, creeaza-l

```bash
curl -sk -X POST \
  'https://127.0.0.1:55000/security/users?pretty=true' \
  -H "Authorization: Bearer $TOKEN" \
  -H 'Content-Type: application/json' \
  -d '{
    "username": "defectdojo-api",
    "password": "PAROLA_COMPLEXA"
  }'
```

### 4. Verifica rolurile disponibile

```bash
curl -sk \
  -H "Authorization: Bearer $TOKEN" \
  'https://127.0.0.1:55000/security/roles?pretty=true'
```

Roluri implicite:

| ID | NAME |
|----|------|
| 1 | administrator |
| 2 | readonly |
| 3 | users_admin |
| 4 | agents_readonly |
| 5 | agents_admin |
| 6 | cluster_readonly |
| 7 | cluster_admin |
| 100 | read_cluster |

Pentru sync e suficient rolul **readonly = ID 2** (doar citire:
agenti, vulnerabilitati, info manager).

### 5. Atribuie rolul readonly noului utilizator

Mai intai afla ID-ul utilizatorului din lista de la pasul 2 (in exemplu e `100`):

```bash
curl -sk -X POST \
  'https://127.0.0.1:55000/security/users/100/roles?role_ids=2&pretty=true' \
  -H "Authorization: Bearer $TOKEN"
```

### 6. Verifica atribuirea

```bash
curl -sk \
  -H "Authorization: Bearer $TOKEN" \
  'https://127.0.0.1:55000/security/users/100?pretty=true'
```

Trebuie sa vezi:

```json
{
   "id": 100,
   "username": "defectdojo-api",
   "allow_run_as": false,
   "roles": [
      2
   ]
}
```

Important: `allow_run_as` trebuie sa fie `false`.

### 7. Testeaza autentificarea cu utilizatorul nou (nu cu administratorul)

```bash
DDTOKEN=$(curl -sk -u 'defectdojo-api:PAROLA_COMPLEXA' \
  -X POST \
  'https://127.0.0.1:55000/security/user/authenticate?raw=true')

echo "$DDTOKEN"
```

Trebuie sa primesti un JWT. Pune apoi `WAZUH_USERNAME=defectdojo-api` si
parola in `.env`, iar pentru OpenSearch foloseste un user read-only separat
(ex. un user read-only de OpenSearch) — vezi tabelul de configurare de mai sus.
