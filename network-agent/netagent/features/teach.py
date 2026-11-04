"""Learning: teach mode (the AI explains everything it does) and quizzes.

    /teach on | off
    /quiz           a networking question with answer buttons (CCNA level)
    /quiz lab       demo only: something breaks somewhere, find it (/quiz hint, /quiz solve)
"""

from __future__ import annotations

import random

from ..result import Button, CommandError, Result

TEACH_PROMPT = """

სასწავლო რეჟიმი ჩართულია. მომხმარებელი ქსელებს სწავლობს (CCNA დონე):
- ყოველ გაშვებულ ბრძანებაზე მოკლედ ახსენი, რატომ აირჩიე და რას აჩვენებს.
- შედეგის მნიშვნელოვანი ველები ახსენი (მაგ. BGP State, OSPF FULL/DR, Status/Protocol) მარტივი ქართულით.
- ტერმინი პირველად რომ გამოჩნდება, ერთი წინადადებით განმარტე.
- ბოლოს დაწერე „📘 რა ვისწავლეთ“ 2–3 პუნქტით და შესთავაზე ერთი სავარჯიშო კითხვა."""

QUESTIONS = [
    ("რომელ OSI დონეზე მუშაობს switch (ჩვეულებრივი, L2)?", ["Data Link (L2)", "Network (L3)", "Transport (L4)", "Physical (L1)"], 0,
     "Switch MAC მისამართებით გადაწყვეტს, სად გაუშვას frame — ეს Data Link დონეა."),
    ("რამდენი გამოსაყენებელი host-ია /26 ქსელში?", ["62", "64", "30", "126"], 0, "2^(32-26) = 64, მინუს network და broadcast = 62."),
    ("OSPF neighbor-ის რომელი მდგომარეობა ნიშნავს, რომ ყველაფერი რიგზეა?", ["FULL", "2-WAY", "EXSTART", "INIT"], 0,
     "FULL — LSDB სინქრონიზებულია. 2-WAY ნორმალურია DROTHER-ებს შორის broadcast ქსელში."),
    ("BGP-ში State 'Active' ნიშნავს:", ["სესია არ არის დამყარებული, ცდილობს დაკავშირებას", "სესია მუშაობს",
                                        "route-ები მიიღო", "neighbor გამორთულია ადმინისტრატორის მიერ"], 0,
     "სახელის მიუხედავად Active ცუდია: TCP სესია ვერ დამყარდა. მუშა სესია ციფრს აჩვენებს (მიღებული prefix-ები)."),
    ("რომელი პორტი აქვს SSH-ს?", ["22", "23", "443", "3389"], 0, "23 — Telnet (დაუშიფრავი), 3389 — RDP."),
    ("რისთვის არის VLAN?", ["L2 ქსელის ლოგიკურად დაყოფისთვის", "სიჩქარის გაზრდისთვის", "IP-ების დასარიგებლად", "შიფრაციისთვის"], 0,
     "ერთი ფიზიკური switch რამდენიმე ცალკე broadcast domain-ად იყოფა."),
    ("trunk პორტი:", ["რამდენიმე VLAN-ს ატარებს tag-ით (802.1Q)", "მხოლოდ ერთ VLAN-ს ატარებს", "მხოლოდ IP ტელეფონებისთვისაა", "გამორთული პორტია"], 0,
     "access პორტი — ერთი VLAN, trunk — ბევრი, 802.1Q tag-ით."),
    ("DHCP-ის 4 ნაბიჯი თანმიმდევრობით:", ["Discover, Offer, Request, Ack", "Request, Offer, Discover, Ack", "Offer, Discover, Ack, Request", "Discover, Request, Offer, Ack"], 0,
     "DORA: კლიენტი ეძებს → სერვერი სთავაზობს → კლიენტი ითხოვს → სერვერი ადასტურებს."),
    ("რა არის default route?", ["0.0.0.0/0", "255.255.255.255/32", "127.0.0.1/8", "169.254.0.0/16"], 0,
     "0.0.0.0/0 ემთხვევა ყველაფერს — სადაც უფრო ზუსტი route არ არის, ტრაფიკი აქ მიდის (ჩვეულებრივ ინტერნეტისკენ)."),
    ("169.254.x.x მისამართი კომპიუტერზე ნიშნავს:", ["DHCP-დან IP ვერ მიიღო", "ინტერნეტი მუშაობს", "სტატიკური IP-ა", "IPv6-ია"], 0,
     "APIPA: DHCP სერვერი არ უპასუხა, კომპიუტერმა თვითონ მიანიჭა link-local მისამართი."),
    ("NAT-ის მთავარი დანიშნულება სახლის როუტერზე:", ["ბევრი შიდა IP ერთი საჯარო IP-ით გადის ინტერნეტში", "Wi-Fi-ს შიფრაცია", "VLAN-ების შექმნა", "DNS სახელების გარდაქმნა"], 0,
     "PAT/overload: შიდა 192.168.x.x მისამართები ერთ საჯარო IP-ს და სხვადასხვა პორტს იყენებენ."),
    ("STP (Spanning Tree) რისთვისაა?", ["L2 loop-ების თავიდან ასაცილებლად", "routing-ისთვის", "IP-ების დასარიგებლად", "ტრაფიკის შიფრაციისთვის"], 0,
     "ორი switch ორი კაბელით = loop და broadcast storm. STP ერთ პორტს ბლოკავს."),
    ("Cisco-ზე 'administratively down' ნიშნავს:", ["ინტერფეისზე shutdown წერია", "კაბელი არ არის შეერთებული", "მეორე მხარე გამორთულია", "duplex mismatch"], 0,
     "ხელით გათიშულია. ჩასართავად: interface ... → no shutdown."),
    ("Status up, Protocol down — ყველაზე ხშირი მიზეზი:", ["L2 პრობლემა (encapsulation, keepalive, მეორე მხარე)", "კაბელი არ არის", "shutdown", "IP არ აქვს"], 0,
     "ფიზიკურად კავშირი არის, მაგრამ L2 პროტოკოლი ვერ შეთანხმდა."),
    ("SNMP community 'public' კონფიგურაციაში რატომაა საშიში?", ["ყველამ იცის — ნებისმიერს შეუძლია მონაცემების წაკითხვა", "ნელს ხდის ქსელს", "IPv6-ს თიშავს", "საშიში არ არის"], 0,
     "ნაგულისხმევი community პაროლივითაა, რომელიც ყველამ იცის. გამოიყენე SNMPv3 ან უნიკალური community + ACL."),
]

LAB_SCENARIOS = {
    "uplink": ("ზოგიერთ მომხმარებელს ინტერნეტი არ აქვს.", "შეამოწმე R1-ის WAN ინტერფეისი და BGP.",
               "R1-ის Gi0/0/0 ჩავარდა → BGP 203.0.113.1 Active → default route არ არის."),
    "cpu": ("ოფისში ყველაფერი ნელა მუშაობს.", "CPU-ს შეამოწმე ყველა switch-ზე.", "SW-Core-1-ის CPU 96%-ზეა."),
    "down": ("სართულზე ქსელი საერთოდ გაქრა.", "რომელი მოწყობილობა არ პასუხობს?", "SW-Access-2 გაითიშა (/status)."),
    "config": ("Gi1/0/10-ზე ჩართული კომპიუტერი სხვა VLAN-ში მოხვდა.", "ბოლო config ცვლილებები და ლოგები ნახე.",
               "ვიღაცამ (gio, 192.168.10.77-დან) SW-Core-1-ზე Gi1/0/10 VLAN 20-ში ჩასვა."),
}


def teach_on(s) -> bool:
    return bool(s.state.get("teach_mode"))


def prompt_extra(s) -> str:
    return TEACH_PROMPT if teach_on(s) else ""


def teach_cmd(s, args, user) -> Result:
    if not args:
        return Result("📘 სასწავლო რეჟიმი: " + ("**ჩართულია**" if teach_on(s) else "გამორთულია"),
                      buttons=[Button("ჩართვა", "/teach on"), Button("გამორთვა", "/teach off")])
    on = args[0].lower() in {"on", "1", "yes", "ჩართვა"}
    s.state.set("teach_mode", on)
    return Result("📘 სასწავლო რეჟიმი ჩაირთო: AI ყველა ნაბიჯს აგიხსნის და ბოლოს „რა ვისწავლეთ“-ს დაწერს. "
                  "ცოდნის შესამოწმებლად: /quiz" if on else "📘 სასწავლო რეჟიმი გამოირთო.")


def _question(rnd: random.Random | None = None) -> Result:
    rnd = rnd or random.Random()
    qi = rnd.randrange(len(QUESTIONS))
    q, options, correct, _ = QUESTIONS[qi]
    order = list(range(len(options)))
    rnd.shuffle(order)
    letters = "ABCD"
    text = f"❓ **{q}**\n" + "\n".join(f"{letters[i]}) {options[o]}" for i, o in enumerate(order))
    return Result(text, buttons=[Button(letters[i], f"/quiz answer {qi} {o}") for i, o in enumerate(order)])


def quiz_cmd(s, args, user) -> Result:
    if args and args[0] == "answer" and len(args) == 3:
        try:
            qi, choice = int(args[1]), int(args[2])
            q, options, correct, why = QUESTIONS[qi]
        except (ValueError, IndexError):
            raise CommandError("არასწორი პასუხი") from None
        stats = s.state.get("quiz_stats") or {"ok": 0, "total": 0}
        stats["total"] += 1
        stats["ok"] += int(choice == correct)
        s.state.set("quiz_stats", stats)
        head = "✅ **სწორია!**" if choice == correct else f"❌ არა. სწორი პასუხი: **{options[correct]}**"
        return Result(f"{head}\n{why}\n\nშედეგი: {stats['ok']}/{stats['total']}", buttons=[Button("➡️ შემდეგი", "/quiz")])
    if args and args[0] in {"lab", "hint", "solve"}:
        from ..demo import lab

        if lab.LAB is None:
            raise CommandError("ლაბის დავალება მხოლოდ დემო რეჟიმში მუშაობს (demo.bat)")
        current = s.state.get("quiz_lab")
        if args[0] == "lab":
            name = random.choice(list(LAB_SCENARIOS))
            lab.LAB.scenario("restore")
            lab.LAB.scenario(name)
            s.state.set("quiz_lab", name)
            return Result(f"🧩 **დავალება:** {LAB_SCENARIOS[name][0]}\nიპოვე მიზეზი — გამოიყენე /status, /health, /logs, "
                          "/runbook, ან ჰკითხე AI-ს (ჯობია სასწავლო რეჟიმში: /teach on).",
                          buttons=[Button("💡 მინიშნება", "/quiz hint"), Button("🔍 პასუხი", "/quiz solve")])
        if not current:
            raise CommandError("ჯერ დაიწყე: /quiz lab")
        if args[0] == "hint":
            return Result(f"💡 {LAB_SCENARIOS[current][1]}", buttons=[Button("🔍 პასუხი", "/quiz solve")])
        s.state.set("quiz_lab", None)
        lab.LAB.scenario("restore")
        return Result(f"🔍 **პასუხი:** {LAB_SCENARIOS[current][2]}\n✅ ქსელი აღდგა.", buttons=[Button("🧩 ახალი დავალება", "/quiz lab")])
    return _question()


COMMANDS = {"teach": teach_cmd, "quiz": quiz_cmd}
HELP = ["/teach on — სასწავლო რეჟიმი (AI ყველაფერს ხსნის) · /quiz — ქსელის კითხვები · /quiz lab — დავალება დემოში"]
BOT_COMMANDS = [("quiz", "ქსელის კითხვები"), ("teach", "სასწავლო რეჟიმი")]
