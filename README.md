# Zadanie

Tento projekt si kladie za cieľ implementovať jednoduchý sieťový sniffer, ktorý dokáže zachytiť a analyzovať sieťovú komunikáciu v reálnom čase. Sieťový sniffer je nástroj, ktorý slúži na zachytávanie a analýzu sieťovej komunikácie a umožňuje používateľom získavať informácie o prenášaných dátach.

# Stručný popis riešenia

Riešením projektu je implementácia jednoduchého sieťového sniffera v jazyku C, ktorý dokáže zachytávať a zobrazovať sieťovú komunikáciu na určenom rozhraní. Program využíva knižnicu libpcap na zachytávanie paketov a zobrazuje ich v hexadecimálnom a ASCII formáte. Taktiež je možné filtrovať pakety podľa rôznych kritérií, ako napríklad protokol IP adresa alebo port. 

# Architektúra programu

## Sieťový sniffer pozostáva z 3 hlavných častí: 

### 1.Spracovanie argumentov príkazového riadka
Pre spracovanie argumentov príkazového riadka bola použitá knižnica `getopt`. Pomocou pola dátových štruktúr `option` sú definované povolené prepínače s dlhou variantou. Následne je vo while cykle volaná funkcia `getopt_long` pomocou ktorej sa postupne spracovávajú jednotlivé argumenty programu. Pri spracovávaní možností ktoré prestavujú nejaký prvok filtra sa nastavujú príznaky prítomnosti, pri argumentoch, ktoré definujú nejakú hodnotu je táto hodnota predaná do odpovedajúcej premennej.

### 2. Príprava sieťového rozhrania a filtrovanie paketov
Príprava sieťového rozhrania, na ktorom sú zachytávané jednotlivé pakety a nastavenie filtra určeného prepínačmi programu boli implementované pomocou funkcií knižnice libpcap.
Medzi použité funkcie patria napríklad:
- `pcap_findalldevs` -vyhladanie dostupných rozhraní na systéme použivateľa
- `pcap_open_live` -otvorenie kanála pre zachytávanie sieťovej komunikácie na danom rozhraní
- `pcap_datalink` -kontrola typu linkovej vrstvy rozhrania
- `pcap_compile` -kompilácia filtra z výrazu zostaveného pomocou argumentov príkazovej riadky
- `pcap_setfilter` -inštalácia filtra na kanál pre zachytávanie
- `pcap_next` -zachytenie samotného paketu
- `pcap_close` -korektné zatvorenie kanála pre zachytávanie

### 3. Parsovanie paketov a výpis výstupu
Parsovanie paketov sa vykonáva za účelom získania požadovaných informácií zo zachytenej sieťovej komunikácie. Využíva sa technika nazývaná casting alebo taktiež pretypovanie, kedy sa surové dáta zo zachyteného paketu(ak je to potrebné tak s odpovedajúcim offsetom) pomocou operácie pretypovania v jazyku C priradia jednotlivým prvkom danej dátovej štruktúry(napr. ether_header, tcphdr, udphdr atd...) a je tak možný jednoduchý prístup k požadovaným dátam. Keďže parsovanie paketu prebieha ako odbalovanie jednotlivých vrstiev enkapsulovaných dát, výstup je vypisovaný postupne po jednotlivých krokoch parsovania v tomto poradí:

1. informácie obsiahnuté v Ethernetovej hlavičke (src MAC, dst MAC)
2. informácie obsiahnuté v hlavičke odpovedajúceho protokolu sieťového protocolu(napr. src IP, dst IP)
3. informácie bosiahnuté v hlavičke odpovedajúceho protokolu transportnej vrstvy (napr. src port, dst port)

Okrem informácií obsiahnutých v samotnom packete je vypísaný aj údaj *timestamp*, ktorý predstavuje čas zachytenia paketu v RFC3339 formáte a dĺžka *length*, ktorá predstavuje dĺžku celého Ethernetového rámca v bytoch. Po výpise spracovaných informácií o pakete je vypísaný surový obsah v hexadecimálnom formáte a ASCII formáte.

# Spustenie programu
    ./ipk-sniffer [-i interface | --interface interface] {-p port [--tcp|-t] [--udp|-u]} [--arp] [--icmp4] [--icmp6] [--igmp] [--mld] {-n num}



# Testovanie programu

Program bol testovaný na virtuálnom stroji odporúčaným v zadaní s aktivovaným referenčným prostredím pre vývoj v jazyku C/C++. Samotné testovanie prebiehalo pomocou porovnávania výstupu jednotlivých spustení implementovaného programu s výstupom programu tcpdump.



Príklady jednotlivých spustení:
    
    sudo ./ipk-sniffer -i enp0s3 --icmp4

timestamp: `2023-04-17T20:59:25Z`

src MAC: `08:00:27:56:aa:92`

dst MAC: `52:54:00:12:35:02`

frame length: `98`

src IP: `10.0.2.15`

dst IP: `142.251.37.110`

    0x0000: 52 54 00 12 35 02 08 00 27 56 AA 92 08 00 45 00 RT..5...'V....E.
    0x0010: 00 54 A6 2D 40 00 40 01 D4 03 0A 00 02 0F 8E FB .T.-@.@.........
    0x0020: 25 6E 08 00 2E 2B 00 02 00 01 2D B3 3D 64 00 00 %n...+....-.=d..
    0x0030: 00 00 99 E7 06 00 00 00 00 00 10 11 12 13 14 15 ................
    0x0040: 16 17 18 19 1A 1B 1C 1D 1E 1F 20 21 22 23 24 25 .......... !"#$%
    0x0050: 26 27 28 29 2A 2B 2C 2D 2E 2F 30 31 32 33 34 35 &'()*+,-./012345
    0x0060: 36 37    


sudo tcpdump -c 1 -e -n -XX -i enp0s3 icmp

tcpdump: verbose output suppressed, use -v[v]... for full protocol decode
listening on enp0s3, link-type EN10MB (Ethernet), snapshot length 262144 bytes
`20:59:25.452533` `08:00:27:56:aa:92` > `52:54:00:12:35:02`, ethertype IPv4 (0x0800)
length `98`: `10.0.2.15` > `142.251.37.110`: ICMP echo request, id 2, seq 1, length 64

    0x0000:  5254 0012 3502 0800 2756 aa92 0800 4500  RT..5...'V....E.
    0x0010:  0054 a62d 4000 4001 d403 0a00 020f 8efb  .T.-@.@.........
    0x0020:  256e 0800 2e2b 0002 0001 2db3 3d64 0000  %n...+....-.=d..
    0x0030:  0000 99e7 0600 0000 0000 1011 1213 1415  ................
    0x0040:  1617 1819 1a1b 1c1d 1e1f 2021 2223 2425  ...........!"#$%
    0x0050:  2627 2829 2a2b 2c2d 2e2f 3031 3233 3435  &'()*+,-./012345
    0x0060:  3637                                     67
    1 packet captured
    2 packets received by filter
    0 packets dropped by kernel

Vyššie uvedený príklad predstavuje porovnanie icmp4 paketu zachyteného implementovaným snifferom oproti programu tcpdump. Ako je možné vidieť na zvýraznených hodnotách, vypísané informácie sa až na formátovanie zhodujú. Podobne porovnaný ARP packet môžeme vidieť v nasledujúcom príklade:


    sudo ./ipk-sniffer -i enp0s3 --arp

timestamp: `2023-04-17T21:24:18Z`

src MAC: `08:00:27:56:aa:92`

dst MAC: `ff:ff:ff:ff:ff:ff`

frame length: `42`

src IP: `10.0.2.15`

dst IP: `142.251.37.110`

    0x0000: FF FF FF FF FF FF 08 00 27 56 AA 92 08 06 00 01 ........'V......
    0x0010: 08 00 06 04 00 01 08 00 27 56 AA 92 0A 00 02 0F ........'V......
    0x0020: FF FF FF FF FF FF 8E FB 25 6E                   ........%n

---
    sudo tcpdump -c 1 -e -n -XX -i enp0s3 arp

tcpdump: verbose output suppressed, use -v[v]... for full protocol decode
listening on enp0s3, link-type EN10MB (Ethernet), snapshot length 262144 bytes
`21:24:18.919567` `08:00:27:56:aa:92` > `ff:ff:ff:ff:ff:ff`, ethertype ARP (0x0806), length `42`: Request who-has `142.251.37.110` (ff:ff:ff:ff:ff:ff) tell `10.0.2.15`, length 28

	0x0000:  ffff ffff ffff 0800 2756 aa92 0806 0001  ........'V......
	0x0010:  0800 0604 0001 0800 2756 aa92 0a00 020f  ........'V......
	0x0020:  ffff ffff ffff 8efb 256e                 ........%n
    1 packet captured
    1 packet received by filter
    0 packets dropped by kernel


Príklad vypísania dostupných rozhraní:

    sudo ./ipk-sniffer

    1. enp0s3 (No description available)
    2. any (Pseudo-device that captures on all interfaces)
    3. lo (No description available)
    4. nflog (Linux netfilter log (NFLOG) interface)
    5. nfqueue (Linux netfilter queue (NFQUEUE) interface)


# Použité zdroje informácií

https://www.tcpdump.org/pcap.html

Fórum k 2. projektu v e-learningu predmetu IPK







