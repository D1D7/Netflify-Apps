# NetAgent: განვითარების გეგმა

**მიმართულება:** NetOps ასისტენტი რეალური ქსელისთვის. მუშაობს ნებისმიერი მწარმოებლის მოწყობილობასთან, Telegram-ში და ტერმინალში. დაწერილია Python-ზე.

## ✅ v0.1 MVP (მზადაა)
- [x] Claude-ის აგენტის ბირთვი tool use-ით, საერთო Telegram-ისა და CLI-სთვის
- [x] Inventory YAML-ში, credentials მხოლოდ `.env`-ში
- [x] Netmiko + TextFSM, read-only ბრძანებები ნებისმიერ პლატფორმაზე
- [x] Vendor command map 20-ზე მეტი პლატფორმისთვის (interfaces, ip, arp, mac, routes, version, neighbors, vlans, config)
- [x] IP, ქსელის ან MAC-ის ძებნა ყველა მოწყობილობაზე პარალელურად
- [x] running-config-ის ანალიზი: IP, ქსელები, VLAN-ები, ინტერფეისები
- [x] ping, traceroute, DNS, TCP port check, subnet კალკულატორი
- [x] Telegram: whitelist, პროგრესის ჩვენება, ფაილის ატვირთვა და ანალიზი
- [x] CLI: ჩატი, `ask`, pipe, `extract` (AI-ს გარეშე)
- [x] უსაფრთხოება: read-only guard, secret masking, audit log

## ✅ v0.2: ტელეფონი, მონიტორინგი, backup (მზადაა)
- [x] Telegram მენიუ ღილაკებით და ბრძანებების სია
- [x] მონიტორინგი: ალერტი მოწყობილობის გათიშვისას და აღდგენისას
- [x] დღიური რეპორტი Telegram-ში და ავტომატური backup
- [x] Config backup (ინახება მხოლოდ ცვლილებისას) და diff: `რა შეიცვალა?`
- [x] Excel ექსპორტი, რომელიც პირდაპირ Telegram-ში მოდის
- [x] ping/traceroute Windows-ზეც
- [x] Docker / docker-compose

## ✅ v0.3: უსაფრთხოება, ხარჯი, ალერტები (მზადაა)
- [x] უსაფრთხოების აუდიტი: Cisco IOS/XE, NX-OS, Juniper, MikroTik, გამოსწორების ბრძანებებით
- [x] დუბლირებული IP მისამართების ძებნა
- [x] Config ცვლილების ალერტი diff-ით
- [x] ალერტების დადუმება (`/mute`, ღილაკი ალერტზე), რომელიც გადატვირთვის შემდეგაც რჩება
- [x] AI ხარჯის აღრიცხვა (`/usage`) და დღიური ბიუჯეტი
- [x] თავისუფალი/დაკავებული IP-ები ქსელში
- [x] `/cmd`: show ბრძანებები ტელეფონიდან, AI-ს გარეშე
- [x] ღილაკები პასუხის ქვეშ (🔄 განახლება, 📊 Excel)
- [x] მიუწვდომელი მოწყობილობების სწრაფი გამოტოვება (TCP pre-check)

## v0.3.x: შემდეგი პატარა გაუმჯობესებები
- [ ] Backup-ების git საცავში შენახვა
- [ ] CPU/მეხსიერების/ინტერფეისის შეცდომების მონიტორინგი (არა მხოლოდ up/down)
- [ ] BGP/OSPF neighbor-ის გათიშვის ალერტი
- [ ] აუდიტის წესები Huawei, Fortinet, Arista-სთვის
- [ ] MAC მისამართის მწარმოებლის ამოცნობა (OUI)

## v0.3: ცვლილებები დადასტურებით
- [ ] Config-ის ცვლილებები ჯერ preview-ს (diff) აჩვენებს, შემდეგ Telegram-ში ჩნდება ღილაკები [✅ დადასტურება] [❌ გაუქმება]
- [ ] კრიტიკული ცვლილებებისთვის PIN ან 2FA
- [ ] ავტომატური rollback (Cisco `configure replace`, Juniper `commit confirmed`)
- [ ] RBAC: viewer, operator და admin როლები
- [ ] Bulk ცვლილებები (მაგ. „ყველა switch-ზე დაამატე VLAN 50“)

## v0.4: ჭკვიანი დიაგნოსტიკა
- [ ] Network discovery CDP/LLDP-ით და ტოპოლოგიის დიაგრამა სურათად Telegram-ში
- [ ] Root cause analysis: „ოფისი 2-ში ინტერნეტი არ მუშაობს“ შემთხვევაში აგენტი თვითონ გადის შემოწმებების ჯაჭვს
- [ ] Path trace A-დან B-მდე
- [ ] Syslog receiver და ლოგების შეჯამება
- [ ] CVE შემოწმება OS-ის ვერსიის მიხედვით
- [ ] SNMP მხარდაჭერა მოწყობილობებისთვის, რომლებსაც SSH არ აქვთ
- [ ] ხმოვანი შეტყობინებები Telegram-ში
- [ ] Runbook-ები (`/runbook vpn-down`)
- [ ] ინციდენტების მეხსიერება
