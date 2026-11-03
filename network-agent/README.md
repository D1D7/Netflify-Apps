# NetAgent: AI ასისტენტი ქსელისთვის

Telegram-ში ან ტერმინალში ჩვეულებრივ ენაზე წერ, მაგალითად „R1-ის IP-ები მაჩვენე“. აგენტი თვითონ უკავშირდება მოწყობილობას, ასრულებს საჭირო `show` ბრძანებებს და შედეგს მოწესრიგებული სახით გიბრუნებს.

> **v0.1 (MVP) მუშაობს მხოლოდ წაკითხვის რეჟიმში.** მოწყობილობაზე ცვლილების შეტანა ტექნიკურად შეუძლებელია (იხ. [უსაფრთხოება](#-უსაფრთხოება)).

## რა შეუძლია

| კითხვის მაგალითი | რას აკეთებს აგენტი |
|---|---|
| `R1-ის ინტერფეისების IP-ები მაჩვენე` | `show ip interface brief` → TextFSM → ცხრილი |
| `192.168.1.57 სადაა ჩართული?` | ეძებს ყველა მოწყობილობის ARP/ინტერფეისებში (MAC-ის შემთხვევაში MAC ცხრილშიც) |
| `რომელ მოწყობილობაზეა 10.10.0.0/24?` | ქსელის ძებნა ყველა მოწყობილობაზე |
| `ყველა მოწყობილობის OS ვერსია` | პარალელურად ყველა მოწყობილობაზე |
| `BGP neighbor-ები R2-ზე` | შესაბამის `show` ბრძანებას თვითონ არჩევს |
| `SW-Core-1-ის კონფიგიდან ამოიღე VLAN-ები და IP-ები` | running-config-ის ანალიზი |
| 📄 config/log ფაილის ატვირთვა | IP, ქსელები, VLAN, MAC, ინტერფეისები და პრობლემები |
| `10.0.0.0/22 დაყავი /26-ებად` | subnet კალკულატორი |
| `example.com-ის MX ჩანაწერები` / `ღიაა 443 10.0.0.5-ზე?` | DNS, TCP port check, ping, traceroute |
| `რა შეიცვალა SW-Core-1-ის კონფიგში?` | იღებს backup-ს, ადარებს წინა ვერსიას და diff-ს ადამიანურ ენაზე ხსნის |
| `ყველა IP Excel-ში გამომიგზავნე` | ქმნის `.xlsx` ფაილს და აგზავნის Telegram-ში |
| `რომელი მოწყობილობაა გათიშული?` | ყველა მოწყობილობის ხელმისაწვდომობის შემოწმება |

### 📱 ტელეფონიდან სამუშაოდ
- **მენიუ ღილაკებით** (`/menu`): სტატუსი, მოწყობილობები, რეპორტი, backup, ყველა IP Excel-ში, OS ვერსიები, გათიშული პორტები, neighbors. ბრძანებების აკრეფა არ გჭირდება.
- **ბრძანებების სია:** შეტყობინების ველში `/`-ზე დაჭერისას ყველა ბრძანება ჩანს.
- **🚨 ალერტები:** ყოველ 5 წუთში მოწყობილობები მოწმდება და გათიშვის ან აღდგენის შემთხვევაში მაშინვე მიიღებ შეტყობინებას (გათიშვის ხანგრძლივობითაც).
- **📊 დილის რეპორტი:** ყოველდღე 09:00-ზე მოდის ჩართული/გათიშული მოწყობილობების სია და ბოლო 24 საათის config ცვლილებები. Backup ამავდროულად ავტომატურად კეთდება.
- **📎 ფაილები:** Excel ექსპორტი პირდაპირ ჩატში მოდის. config/log ფაილის ატვირთვის შემთხვევაში ბოტი მის ანალიზს გიბრუნებს.

`/status`, `/backup`, `/report` და `/devices` AI-ს არ იყენებენ, ამიტომ სწრაფია და API-ს ხარჯი არ აქვს.

**მწარმოებლები:** Netmiko-ს მიერ მხარდაჭერილი ნებისმიერი მოწყობილობა (80+ პლატფორმა). მზა ბრძანებების რუკა უკვე აქვს ამ პლატფორმებს: Cisco IOS/XE/NX-OS/XR/ASA, Arista, Juniper, MikroTik, Huawei, HP Comware/ProCurve, Aruba CX, Fortinet, Palo Alto, Dell OS10, Extreme, VyOS/EdgeRouter, Linux. დანარჩენ მოწყობილობებზე აგენტი `run_show_command`-ს იყენებს და ბრძანებას მოწყობილობის საკუთარი სინტაქსით წერს.

## ინსტალაცია

საჭიროა Python 3.10 ან უფრო ახალი.

```bash
cd network-agent
python3 -m venv .venv && source .venv/bin/activate
pip install -r requirements.txt

cp .env.example .env
cp inventory/devices.example.yaml inventory/devices.yaml
```

### 1. Anthropic API key
[console.anthropic.com](https://console.anthropic.com) → API Keys. ჩაწერე `.env`-ში: `ANTHROPIC_API_KEY=...`

### 2. Telegram ბოტი
1. Telegram-ში გახსენი **@BotFather** → `/newbot` → მიჰყევი ინსტრუქციას და მიიღე ტოკენი.
2. `.env`-ში ჩაწერე `TELEGRAM_BOT_TOKEN=...`
3. გაუშვი ბოტი (`python -m netagent.telegram_bot`) და მიწერე მას `/id`.
4. მიღებული ID ჩაწერე `.env`-ში `TELEGRAM_ALLOWED_USERS=123456789` სახით (რამდენიმე ID მძიმით გამოყავი) და ბოტი გადატვირთე.

### 3. მოწყობილობები
შეავსე `inventory/devices.yaml`:

```yaml
credentials:
  default:
    username_env: NET_USER      # .env-ის ცვლადის სახელი და არა პაროლი!
    password_env: NET_PASS
devices:
  R1:
    host: 10.0.0.1
    device_type: cisco_ios      # Netmiko platform
    site: HQ
    role: router
```

პაროლები ინახება მხოლოდ `.env`-ში. `inventory/devices.yaml` და `.env` `.gitignore`-შია, ამიტომ git-ში არ მოხვდება.

> 💡 რეკომენდაცია: აგენტისთვის მოწყობილობებზე შექმენი ცალკე მომხმარებელი, რომელსაც **მხოლოდ წაკითხვის უფლება** აქვს (Cisco: `privilege 1` ან `parser view`, MikroTik: `read` group, Juniper: `read-only` class). ასე დაცვის მეორე ფენა გექნება.

## გაშვება

```bash
# Telegram ბოტი
python -m netagent.telegram_bot

# ტერმინალი: ინტერაქტიული ჩატი
python -m netagent

# ერთი კითხვა
python -m netagent ask "R1-ის ინტერფეისები"

# ფაილის ან ბრძანების output-ის გადაცემა pipe-ით
cat running.cfg | python -m netagent ask "ამოიღე VLAN-ები და IP-ები"

# AI-ს გარეშე, ლოკალურად: IP/VLAN/MAC-ის ამოღება ფაილიდან
python -m netagent extract running.cfg
python -m netagent extract running.cfg --json

# inventory-ს სია
python -m netagent devices

# რომელი მოწყობილობაა ჩართული/გათიშული
python -m netagent status

# config-ების backup (ყველა, ან ფილტრით, მაგ. HQ)
python -m netagent backup
python -m netagent backup HQ

# რა შეიცვალა R1-ზე ბოლო 24 საათში
python -m netagent diff R1 --hours 24

# რეპორტი
python -m netagent report
```

Telegram-ის ბრძანებები: `/menu`, `/status`, `/report`, `/backup`, `/devices`, `/reset` (საუბრის თავიდან დაწყება), `/id`, `/help`.

### Backup-ები
Config-ები ინახება `backups/<მოწყობილობა>/<თარიღი>.cfg` ფაილებში. ახალი ფაილი იქმნება **მხოლოდ მაშინ, როცა config შეიცვალა**, ამიტომ ფაილების სია ცვლილებების ისტორიაცაა. დროის ხაზები და მსგავსი ცვალებადი სტრიქონები (`! Last configuration change...`) შედარებისას იგნორირდება.

> ⚠️ Backup-ებში პაროლები დაფარულია (`<masked>`), რადგან მათ AI კითხულობს. ამიტომ ეს backup-ები ცვლილებების თვალყურის დევნებისთვისაა და არა მოწყობილობის სრული აღდგენისთვის.

## 🔒 უსაფრთხოება

| ფენა | რას აკეთებს |
|---|---|
| **Read-only guard** (`security.py`) | ყველა ბრძანება მოწმდება მოწყობილობაზე გაგზავნამდე. დაშვებულია მხოლოდ `show`, `display` და `get`, RouterOS-ზე `print`/`export`, Linux-ზე ბრძანებების allowlist. იბლოკება `configure`, `reload`, `write`, `delete`, `clear`, `debug`, `set`, `add` და სხვა. |
| **Secret masking** | პაროლები, enable secret, SNMP community, TACACS/RADIUS key, PSK და private key იფარება (`<masked>`) მანამ, სანამ ტექსტი Claude-სთან ან ჩატში მოხვდება. |
| **Credentials** | Claude-ს credentials არასოდეს უჩანს. მისთვის მხოლოდ ბრძანების შედეგია ხილული. |
| **Telegram whitelist** | ბოტი პასუხობს მხოლოდ `TELEGRAM_ALLOWED_USERS`-ში ჩაწერილ მომხმარებლებს. |
| **Audit log** | ყველა მოქმედება (ვინ, რა ხელსაწყო, რა პარამეტრებით) იწერება `logs/audit.jsonl`-ში. |
| **Prompt injection** | მოწყობილობის output-ს და ატვირთულ ფაილებს აგენტი მონაცემად აღიქვამს და მათში ჩაწერილ ინსტრუქციებს არ ასრულებს. |

## არქიტექტურა

```
Telegram (python-telegram-bot)     Terminal (rich)
              \                        /
               ▼                      ▼
          ┌──────────────────────────────┐
          │ agent.py: Claude + tool loop  │  ← ერთი ბირთვი ორივე ინტერფეისისთვის
          └──────────────┬───────────────┘
                         │ tools/__init__.py (validation, masking, audit)
     ┌───────────┬───────┴──────┬────────────┬────────────┐
     ▼           ▼              ▼            ▼            ▼
 device.py   network.py     subnet.py    extract.py   inventory.py
 Netmiko +   ping, trace,   CIDR calc    IP/VLAN/MAC  devices.yaml
 TextFSM     DNS, port                   ამოღება      + .env creds
```

```
network-agent/
├── netagent/
│   ├── agent.py          # Claude-ის tool-use ციკლი, სესიები
│   ├── telegram_bot.py   # Telegram ინტერფეისი
│   ├── cli.py            # ტერმინალის ინტერფეისი
│   ├── security.py       # read-only guard, secret masking
│   ├── inventory.py      # მოწყობილობები და credentials
│   ├── formatting.py     # Markdown → Telegram HTML
│   ├── health.py         # ხელმისაწვდომობა + მონიტორინგი
│   ├── backup.py         # config backup და diff
│   ├── report.py         # დღიური რეპორტი
│   ├── export.py         # Excel ექსპორტი
│   ├── audit.py
│   ├── config.py
│   └── tools/
│       ├── __init__.py   # tool-ების აღწერა Claude-სთვის + dispatcher
│       ├── device.py     # SSH, vendor command map, ქსელში ძებნა
│       ├── network.py    # ping, traceroute, DNS, port check
│       ├── subnet.py
│       └── extract.py
├── inventory/devices.example.yaml
├── tests/
├── .env.example
├── Dockerfile, docker-compose.yml
└── PLAN.md               # შემდეგი ეტაპები
```

## კონფიგურაცია (`.env`)

| ცვლადი | ნაგულისხმევი | აღწერა |
|---|---|---|
| `ANTHROPIC_API_KEY` | — | Claude API key |
| `NETAGENT_MODEL` | `claude-opus-5-5` | Claude მოდელი |
| `NETAGENT_EFFORT` | `medium` | `low` ნიშნავს უფრო სწრაფ და იაფ პასუხს, `high` კი უფრო საფუძვლიან ანალიზს |
| `TELEGRAM_BOT_TOKEN` | — | @BotFather-ის ტოკენი |
| `TELEGRAM_ALLOWED_USERS` | — | დაშვებული user ID-ები |
| `NETAGENT_INVENTORY` | `inventory/devices.yaml` | inventory ფაილი |
| `NETAGENT_DEVICE_TIMEOUT` | `20` | SSH timeout (წამი) |
| `NETAGENT_MAX_PARALLEL` | `10` | რამდენ მოწყობილობას დაუკავშირდეს ერთდროულად |
| `NETAGENT_MONITOR_INTERVAL` | `5` | მონიტორინგის ინტერვალი წუთებში (`0` = გამორთული) |
| `NETAGENT_DAILY_REPORT` | `09:00` | დღიური რეპორტისა და backup-ის დრო (ცარიელი = გამორთული) |
| `NETAGENT_TZ` | `Asia/Tbilisi` | დროის სარტყელი |
| `NETAGENT_BACKUP_DIR` | `backups` | backup-ების საქაღალდე |
| `NETAGENT_EXPORT_DIR` | `exports` | Excel ფაილების საქაღალდე |

## ტესტები

```bash
pip install -r requirements-dev.txt
python -m pytest -q
```

## სერვერზე მუდმივად გაშვება: Docker (ყველაზე მარტივი)

```bash
cp .env.example .env                                     # შეავსე
cp inventory/devices.example.yaml inventory/devices.yaml # შეავსე
docker compose up -d --build
docker compose logs -f        # ლოგები
```

ბოტი ავტომატურად ჩაირთვება სერვერის გადატვირთვის შემდეგაც. Backup-ები, ექსპორტები და ლოგები სერვერზე ინახება `backups/`, `exports/` და `logs/` საქაღალდეებში.

## სერვერზე მუდმივად გაშვება (systemd)

```ini
# /etc/systemd/system/netagent.service
[Unit]
Description=NetAgent Telegram bot
After=network-online.target

[Service]
WorkingDirectory=/opt/network-agent
ExecStart=/opt/network-agent/.venv/bin/python -m netagent.telegram_bot
Restart=always
User=netagent

[Install]
WantedBy=multi-user.target
```

```bash
sudo systemctl enable --now netagent
journalctl -u netagent -f
```

აგენტი უნდა გაეშვას ისეთ სერვერზე, საიდანაც მოწყობილობების management ქსელზე SSH წვდომა არსებობს.
