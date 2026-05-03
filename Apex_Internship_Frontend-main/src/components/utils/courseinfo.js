// courseinfo.js

export const courseData = {

    // --- Fundamental Learning Track ---
    // Course: Cyber Security Fundamental

    "cyber-security-fundamentals": {
        id: "cyber-security-fundamentals",
        title: "Cyber Security Fundamentals",
        tags: [
            { label: "Cryptography", icon: "lock" },
            { label: "Fundamental Track", icon: "shield" },
            { label: "Governance", icon: "file" }
        ],
        track: "Fundamental Track",
        level: "Beginner",
        duration: "9 Weeks (1 Chapter per week)",
        description: "Cyber Security Fundamentals gives you a clear and practical introduction to how modern security works. You’ll learn the basics of threats, secure design, cryptography, identity and access management, network protection, application security, monitoring, and incident response. The course builds your understanding step-by-step so you can see how each layer works together to keep systems and data safe, preparing you for more advanced security learning.",
        
        learningObjectives: [
            "Master the CIA Triad and Risk Management frameworks",
            "Analyze common threats like Phishing, Malware, and DDoS",
            "Design secure network architectures (DMZ, Zero Trust)",
            "Understand Cryptography, PKI, and Encryption standards",
            "Implement Identity & Access Management (IAM) controls",
            "Incident Response and Disaster Recovery plans"
        ],
        prerequisites: [
            "Basic computer literacy and file management skills",
            "Understanding of how the internet works (HTTP, IP addresses)",
            "No prior coding or cybersecurity experience required",
            "A Windows, Mac, or Linux computer with internet access"
        ],

        modules: [
            // Chapter 1
            { 
                title: "Chapter 1: Security Fundamentals & Governance", 
                lessons: [
                    { id: "cia-triad-confidentiality-integrity-availability", title: "CIA Triad (Confidentiality, Integrity, Availability)", type: "video", duration: "12m 30s", completed: true }, 
                    { id: "risk-management-concepts-&-process", title: "Risk Management Concepts & Process", type: "video", duration: "15m", completed: true },
                    { id: "security-policies-&-frameworks-nist-iso-27001", title: "Security Policies & Frameworks (NIST, ISO 27001)", type: "video", duration: "20m 10s", completed: false },
                    { id: "compliance-&-legal-regulations-gdpr-hipaa-pci-dss", title: "Compliance & Legal Regulations (GDPR, HIPAA, PCI-DSS)", type: "video", duration: "8m", completed: false }
                ] 
            },
            // Chapter 2
            { 
                title: "Chapter 2: Threats, Attacks & Vulnerabilities", 
                lessons: [
                    { id: "types-of-threat-actors-nation-state-insider-hacktivist", title: "Types of Threat Actors (Nation-State, Insider, Hacktivist)", type: "video", duration: "18m 05s", completed: false },
                    { id: "social-engineering-attacks-phishing-pretexting", title: "Social Engineering Attacks (Phishing, Pretexting)", type: "video", duration: "14m 20s", completed: false },
                    { id: "malware-types-ransomware-trojans-rootkits-spyware", title: "Malware Types (Ransomware, Trojans, Rootkits, Spyware)", type: "video", duration: "16m", completed: false },
                    { id: "common-network-attacks-ddos-mitm-dns-spoofing", title: "Common Network Attacks (DDoS, MITM, DNS Spoofing)", type: "video", duration: "7m", completed: false }
                ]
            },
            // Chapter 3
            { 
                title: "Chapter 3: Security Architecture & Design", 
                lessons: [
                    { id: "defense-in-depth-strategy", title: "Defense-in-Depth Strategy", type: "video", duration: "10m 50s", completed: false },
                    { id: "security-models-bell-lapadula-biba-clark-wilson", title: "Security Models (Bell-LaPadula, Biba, Clark-Wilson)", type: "video", duration: "25m", completed: false },
                    { id: "secure-system-design-principles-least-privilege-separation-of-duties", title: "Secure System Design Principles (Least Privilege, Separation of Duties)", type: "video", duration: "17m 30s", completed: false },
                    { id: "network-architecture-security-dmz-zero-trust-architecture", title: "Network Architecture Security (DMZ, Zero Trust Architecture)", type: "video", duration: "22m 00s", completed: false },
                    { id: "virtualization-&-cloud-security-considerations", title: "Virtualization & Cloud Security Considerations", type: "video", duration: "12m", completed: false },
                    { id: "physical-security-controls-access-control-surveillance", title: "Physical Security Controls (Access Control, Surveillance)", type: "video", duration: "5m", completed: false }
                ]
            },
            // Chapter 4
            { 
                title: "Chapter 4: Cryptography & PKI", 
                lessons: [
                    { id: "cryptographic-concepts-symmetric-vs-asymmetric-hashing-salting", title: "Cryptographic Concepts (Symmetric vs. Asymmetric, Hashing, Salting)", type: "video", duration: "28m 45s", completed: false },
                    { id: "encryption-algorithms-aes-rsa-ecc-sha-256", title: "Encryption Algorithms (AES, RSA, ECC, SHA-256)", type: "video", duration: "18m", completed: false },
                    { id: "public-key-infrastructure-pki-&-digital-certificates", title: "Public Key Infrastructure (PKI) & Digital Certificates", type: "video", duration: "21m 15s", completed: false },
                    { id: "secure-email-communication-pgp-s/mime", title: "Secure Email Communication (PGP, S/MIME)", type: "video", duration: "10m", completed: false }
                ]
            },
            // Chapter 5
            { 
                title: "Chapter 5: Identity & Access Management (IAM)", 
                lessons: [
                    { id: "authentication-factors-you-know-have-are", title: "Authentication Factors (You Know, Have, Are)", type: "video", duration: "14m 10s", completed: false },
                    { id: "multi-factor-authentication-mfa-&-single-sign-on-sso", title: "Multi-Factor Authentication (MFA) & Single Sign-On (SSO)", type: "video", duration: "16m 30s", completed: false },
                    { id: "access-control-models-rbac-abac-mac-dac", title: "Access Control Models (RBAC, ABAC, MAC, DAC)", type: "video", duration: "24m", completed: false },
                    { id: "identity-federation-&-oauth-saml-openid-connect", title: "Identity Federation & OAuth, SAML, OpenID Connect", type: "video", duration: "10m", completed: false }
                ]
            },
            // Chapter 6
            { 
                title: "Chapter 6: Secure Network Design & Implementation", 
                lessons: [
                    { id: "secure-protocols-tls-ipsec-ssh-sftp", title: "Secure Protocols (TLS, IPSec, SSH, SFTP)", type: "video", duration: "19m 50s", completed: false },
                    { id: "network-segmentation-&-microsegmentation", title: "Network Segmentation & Microsegmentation", type: "video", duration: "17m", completed: false },
                    { id: "firewalls-stateful-stateless-wafs-&-ids/ips", title: "Firewalls (Stateful, Stateless, WAFs) & IDS/IPS", type: "video", duration: "25m 00s", completed: false },
                    { id: "vpns-&-remote-access-security-l2tp-ssl-vpn", title: "VPNs & Remote Access Security (L2TP, SSL-VPN)", type: "video", duration: "12m", completed: false }
                ]
            },
            // Chapter 7
            { 
                title: "Chapter 7: Endpoint & Application Security", 
                lessons: [
                    { id: "endpoint-protection-edr-anti-malware-host-firewall", title: "Endpoint Protection (EDR, Anti-malware, Host Firewall)", type: "video", duration: "13m 20s", completed: false },
                    { id: "secure-coding-practices-owasp-top-10-input-validation", title: "Secure Coding Practices (OWASP Top 10, Input Validation)", type: "video", duration: "22m", completed: false },
                    { id: "web-application-security-sql-injection-xss-csrf", title: "Web Application Security (SQL Injection, XSS, CSRF)", type: "video", duration: "28m 40s", completed: false },
                    { id: "api-security-&-secure-software-development-lifecycle-sdlc", title: "API Security & Secure Software Development Lifecycle (SDLC)", type: "video", duration: "15m", completed: false }
                ]
            },
            // Chapter 8
            { 
                title: "Chapter 8: Security Operations & Incident Response", 
                lessons: [
                    { id: "security-monitoring-&-logging-siem-soar-syslog", title: "Security Monitoring & Logging (SIEM, SOAR, Syslog)", type: "video", duration: "20m 00s", completed: false },
                    { id: "threat-hunting-&-threat-intelligence-mitre-att&ck-ioc", title: "Threat Hunting & Threat Intelligence (MITRE ATT&CK, IOC)", type: "video", duration: "16m 10s", completed: false },
                    { id: "incident-response-frameworks-nist-800-61-sans", title: "Incident Response Frameworks (NIST 800-61, SANS)", type: "video", duration: "23m", completed: false },
                    { id: "forensic-techniques-&-chain-of-custody", title: "Forensic Techniques & Chain of Custody", type: "video", duration: "10m", completed: false }
                ]
            },
            // Chapter 9
            { 
                title: "Chapter 9: Business Continuity & Disaster Recovery", 
                lessons: [
                    { id: "backup-strategies-full-incremental-differential-snapshots", title: "Backup Strategies (Full, Incremental, Differential, Snapshots)", type: "video", duration: "15m 30s", completed: false },
                    { id: "disaster-recovery-strategies-hot-warm-cold-sites", title: "Disaster Recovery Strategies (Hot, Warm, Cold Sites)", type: "video", duration: "18m", completed: false },
                    { id: "business-continuity-planning-bcp-&-risk-assessments", title: "Business Continuity Planning (BCP) & Risk Assessments", type: "video", duration: "12m 50s", completed: false },
                    { id: "high-availability-&-redundancy-raid-load-balancers-failover-clusters", title: "High Availability & Redundancy (RAID, Load Balancers, Failover Clusters)", type: "video", duration: "7m", completed: false }
                ]
            },
        ]
    },

    // Course: Networking Essentials

    "networking-essentials": {
        id: "networking-essentials",
        title: "Networking Essentials",
        tags: [
            { label: "Fundamental Track", icon: "shield" },
            { label: "Networking", icon: "globe" },
            { label: "Beginner Friendly", icon: "code" }
        ],
        track: "Fundamental Track",
        level: "Beginner",
        duration: "5 Weeks",
        description: "Networking Essentials gives you a clear and practical introduction to how modern networking works. You’ll learn the fundamental of TCP/IP, Ethernet, switching, routing, VLANs, wireless communication, core protocols, network diagnostics, device configuration, and traffic flow. The course builds your understanding step-by-step so you can see how each layer works together to move data safely and reliably, preparing you for more advanced networking learning.",
       
        learningObjectives: [
            "Understand the TCP/IP model and its role in communication",
            "Configure basic networking components like IP, DNS, and DHCP",
            "Analyze how routing, switching, and VLANs operate in real networks",
            "Troubleshoot connectivity issues using essential diagnostic tools",
            "Learn core protocols such as HTTP, SSH, FTP, and their behaviors",
            "Build a foundation for advanced networking and security concepts"
        ],
       
        prerequisites: [
            "Basic computer usage and comfort with operating systems",
            "General understanding of how websites and online services work",
            "No prior networking experience required for this course",
            "A Windows, Mac, or Linux computer with stable internet access"
        ],
       
        modules: [
            {
            // Chapter 1: Network Foundations & TCP/IP Architecture
                title: "Chapter 1: Network Foundations & TCP/IP Architecture",
                lessons: [
                    { id: "history-and-evolution-of-networking", title: "History and Evolution of Networking", type: "video", duration: "10m 15s", completed: false },
                    { id: "definition-and-types-of-networks-lan-wan-man-pan", title: "Definition and Types of Networks (LAN, WAN, MAN, PAN)", type: "video", duration: "12m 30s", completed: false },
                    { id: "network-topologies-bus-ring-star-mesh", title: "Network Topologies: Bus, Ring, Star, Mesh", type: "video", duration: "15m 00s", completed: false },
                    { id: "overview-of-tcp/ip-model-and-its-layers", title: "Overview of TCP/IP Model and its Layers", type: "video", duration: "20m 45s", completed: false },
                    { id: "transport-layer-tcp-handshake-tcp-vs-udp-error-recovery", title: "Transport Layer: TCP Handshake, TCP vs. UDP, Error Recovery", type: "video", duration: "25m 10s", completed: false },
                    { id: "network-layer-ipv4-vs-ipv6-routing-concepts", title: "Network Layer: IPv4 vs. IPv6, Routing Concepts", type: "video", duration: "18m 20s", completed: false },
                    { id: "data-link-layer-ethernet-protocols-mac-addresses-frame-structure", title: "Data Link Layer: Ethernet Protocols, MAC Addresses, Frame Structure", type: "video", duration: "14m 50s", completed: false },
                    { id: "physical-layer-cabling-types-utp-vs-fiber-duplex-concepts", title: "Physical Layer: Cabling Types, UTP vs. Fiber, Duplex Concepts", type: "video", duration: "11m 40s", completed: false },
                    { id: "data-encapsulation-and-message-flow", title: "Data Encapsulation and Message Flow", type: "video", duration: "16m 00s", completed: false },
                    { id: "why-tcp/ip-replaced-the-osi-model", title: "Why TCP/IP Replaced the OSI Model", type: "video", duration: "8m 55s", completed: false },
                    
                    // Core Protocols:
                    { id: "core-protocols-http/https-methods-status-codes-ssl/tls", title: "Core Protocols: HTTP/HTTPS (Methods, Status Codes, SSL/TLS)", type: "video", duration: "22m 30s", completed: false },
                    { id: "core-protocols-ftp-modes-commands-security", title: "Core Protocols: FTP (Modes, Commands, Security)", type: "video", duration: "10m 05s", completed: false },
                    { id: "core-protocols-email-protocols-smtp-pop3-imap", title: "Core Protocols: Email Protocols (SMTP, POP3, IMAP)", type: "video", duration: "15m 40s", completed: false },
                    { id: "core-protocols-dns-resolution-process-record-types-dnssec", title: "Core Protocols: DNS (Resolution Process, Record Types, DNSSEC)", type: "video", duration: "28m 00s", completed: false },
                    { id: "core-protocols-dhcp-&-dhcpv6-lease-process-message-types", title: "Core Protocols: DHCP & DHCPv6 (Lease Process, Message Types)", type: "video", duration: "13m 25s", completed: false },
                    { id: "core-protocols-snmp-versions-operations-components", title: "Core Protocols: SNMP (Versions, Operations, Components)", type: "video", duration: "9m 10s", completed: false },
                    { id: "core-protocols-ssh-&-ntp-secure-remote-access-tunneling", title: "Core Protocols: SSH & NTP (Secure Remote Access, Tunneling)", type: "video", duration: "11m 55s", completed: false },
                ]
            },
            // Chapter 2: LAN & WAN Fundamentals
            {
                title: "Chapter 2: LAN & WAN Fundamentals",
                lessons: [
                    // LAN Topics:
                    { id: "lan-fundamentals-and-physical-layer-standards", title: "LAN Fundamentals and Physical Layer Standards", type: "video", duration: "14m 30s", completed: false },
                    { id: "ethernet-overview-utp/fiber-speed-standards", title: "Ethernet Overview: UTP/Fiber, Speed Standards", type: "video", duration: "18m 00s", completed: false },
                    { id: "cabling-and-pinouts", title: "Cabling and Pinouts", type: "video", duration: "9m 45s", completed: false },
                    { id: "error-detection-using-the-fcs-field", title: "Error Detection using the FCS Field", type: "video", duration: "7m 55s", completed: false },
                    { id: "wireless-lan-wi-fi-basics", title: "Wireless LAN (Wi-Fi) Basics", type: "video", duration: "11m 30s", completed: false },
                    { id: "duplex-and-collision-domain-concepts", title: "Duplex and Collision Domain Concepts", type: "video", duration: "15m 15s", completed: false },
                    // WAN Topics:
                    { id: "introduction-to-wan-and-leased-line-technologies", title: "Introduction to WAN and Leased Line Technologies", type: "video", duration: "12m 10s", completed: false },
                    { id: "hdlc-protocol-and-ethernet-wan-implementations", title: "HDLC Protocol and Ethernet WAN Implementations", type: "video", duration: "16m 50s", completed: false },
                    { id: "ip-packet-routing-across-lan-and-wan-environments", title: "IP Packet Routing Across LAN and WAN Environments", type: "video", duration: "20m 00s", completed: false },
                    { id: "ping-traceroute-and-icmp-for-network-diagnostics", title: "Ping, Traceroute, and ICMP for Network Diagnostics", type: "video", duration: "14m 40s", completed: false },
                    { id: "routing-logic-host-forwarding-router-communication", title: "Routing Logic: Host Forwarding, Router Communication", type: "video", duration: "18m 25s", completed: false },
                ]
            },
            // Chapter 3: Switching Concepts & VLAN Configuration
            {
                title: "Chapter 3: Switching Concepts & VLAN Configuration",
                lessons: [
                    // Switching Fundamentals:
                    { id: "lan-switching-and-data-plane-overview", title: "LAN Switching and Data Plane Overview", type: "video", duration: "13m 15s", completed: false },
                    { id: "mac-learning-and-forwarding", title: "MAC Learning and Forwarding", type: "video", duration: "10m 00s", completed: false },
                    { id: "managing-mac-address-tables", title: "Managing MAC Address Tables", type: "video", duration: "8m 30s", completed: false },
                    { id: "spanning-tree-protocol-stp-and-rstp", title: "Spanning Tree Protocol (STP) and RSTP", type: "video", duration: "28m 45s", completed: false },
                    { id: "stp-root-bridge-election-port-roles-and-interface-states", title: "STP: Root Bridge Election, Port Roles, and Interface States", type: "video", duration: "19m 50s", completed: false },
                    { id: "troubleshooting-stp-and-rstp", title: "Troubleshooting STP and RSTP", type: "video", duration: "11m 20s", completed: false },
                    { id: "etherchannel-configuration-manual-and-dynamic", title: "EtherChannel Configuration: Manual and Dynamic", type: "video", duration: "14m 10s", completed: false },
                    { id: "load-distribution-across-multiple-interfaces", title: "Load Distribution Across Multiple Interfaces", type: "video", duration: "9m 05s", completed: false },
                    // VLAN Fundamentals:
                    { id: "vlan-concepts-and-purposes", title: "VLAN Concepts and Purposes", type: "video", duration: "16m 30s", completed: false },
                    { id: "vlan-tagging-802.1q-and-multi-switch-design", title: "VLAN Tagging (802.1Q) and Multi-Switch Design", type: "video", duration: "21m 00s", completed: false },
                    { id: "vlan-trunking-protocol-vtp-configuration", title: "VLAN Trunking Protocol (VTP) Configuration", type: "video", duration: "15m 00s", completed: false },
                    { id: "vlan-troubleshooting-trunk-mismatches-native-vlan-conflicts", title: "VLAN Troubleshooting: Trunk Mismatches, Native VLAN Conflicts", type: "video", duration: "10m 45s", completed: false },
                ]
            },
            // Chapter 4: Device Management & Control Plane
            {
                title: "Chapter 4: Device Management & Control Plane",
                lessons: [
                    // Management Plane Topics:
                    { id: "securing-user-and-privilege-modes", title: "Securing User and Privilege Modes", type: "video", duration: "9m 30s", completed: false },
                    { id: "local-authentication-and-password-policies", title: "Local Authentication and Password Policies", type: "video", duration: "11m 00s", completed: false },
                    { id: "aaa-authentication-authorization-accounting-implementation", title: "AAA (Authentication, Authorization, Accounting) Implementation", type: "video", duration: "17m 40s", completed: false },
                    { id: "ipv4-configuration-manual-vs-dynamic", title: "IPv4 Configuration (Manual vs. Dynamic)", type: "video", duration: "12m 15s", completed: false },
                    { id: "verifying-network-connectivity-and-device-configuration", title: "Verifying Network Connectivity and Device Configuration", type: "video", duration: "10m 20s", completed: false },
                    // Control Plane Topics:
                    { id: "interface-configuration-speed-duplex-description", title: "Interface Configuration (Speed, Duplex, Description)", type: "video", duration: "14m 50s", completed: false },
                    { id: "range-command-configuration-and-interface-state-management", title: "Range Command Configuration and Interface State Management", type: "video", duration: "8m 10s", completed: false },
                    { id: "autonegotiation-concepts-and-troubleshooting", title: "Autonegotiation Concepts and Troubleshooting", type: "video", duration: "13m 20s", completed: false },
                    { id: "interface-status-monitoring-and-error-diagnosis", title: "Interface Status Monitoring and Error Diagnosis", type: "video", duration: "9m 55s", completed: false },
                    { id: "layer-1-and-duplex-mismatch-resolution", title: "Layer 1 and Duplex Mismatch Resolution", type: "video", duration: "11m 15s", completed: false },
                ]
            },
            // Chapter 5: IPv4 & IPv6 Routing, Subnetting, and Dynamic Protocols
            {
                title: "Chapter 5: IPv4 & IPv6 Routing, Subnetting, and Dynamic Protocols",
                lessons: [
                    // IPv4 & IPv6 Addressing and Subnetting:
                    { id: "ipv4-addressing-classes-private/public-ips-subnet-masks", title: "IPv4 Addressing: Classes, Private/Public IPs, Subnet Masks", type: "video", duration: "18m 40s", completed: false },
                    { id: "ipv6-addressing-global-unicast-link-local-multicast-anycast", title: "IPv6 Addressing: Global Unicast, Link-Local, Multicast, Anycast", type: "video", duration: "15m 20s", completed: false },
                    { id: "subnetting-calculations-and-cidr-notation", title: "Subnetting Calculations and CIDR Notation", type: "video", duration: "25m 00s", completed: false },
                    { id: "vlsm-variable-length-subnet-masking-for-optimized-addressing", title: "VLSM (Variable Length Subnet Masking) for Optimized Addressing", type: "video", duration: "14m 30s", completed: false },
                    { id: "ipv6-prefix-allocation-and-subnet-planning", title: "IPv6 Prefix Allocation and Subnet Planning", type: "video", duration: "10m 50s", completed: false },
                    { id: "address-summarization-and-route-aggregation", title: "Address Summarization and Route Aggregation", type: "video", duration: "16m 15s", completed: false },
                    // Routing Fundamentals & Dynamic Protocols:
                    { id: "router-fundamentals-and-enterprise-vs-soho-architectures", title: "Router Fundamentals and Enterprise vs. SOHO Architectures", type: "video", duration: "12m 00s", completed: false },
                    { id: "static-routing-network-default-and-floating-routes", title: "Static Routing: Network, Default, and Floating Routes", type: "video", duration: "18m 50s", completed: false },
                    { id: "vlan-routing-via-layer-3-switches-svi-and-routed-ports", title: "VLAN Routing via Layer 3 Switches (SVI and Routed Ports)", type: "video", duration: "21m 10s", completed: false },
                    { id: "router-on-a-stick-roas-implementation", title: "Router-on-a-Stick (ROAS) Implementation", type: "video", duration: "13m 05s", completed: false },
                    { id: "dynamic-routing-protocols-ospf-open-shortest-path-first", title: "Dynamic Routing Protocols: OSPF (Open Shortest Path First)", type: "video", duration: "24m 40s", completed: false },
                    { id: "eigrp-enhanced-interior-gateway-routing-protocol-configuration-and-metrics", title: "EIGRP (Enhanced Interior Gateway Routing Protocol): Configuration and Metrics", type: "video", duration: "22m 30s", completed: false },
                    { id: "route-redistribution-and-distribution", title: "Route Redistribution and Distribution", type: "video", duration: "15m 55s", completed: false },
                    { id: "longest-prefix-match-and-routing-verification", title: "Longest Prefix Match and Routing Verification", type: "video", duration: "10m 10s", completed: false },
                ]
            }
        ]
    },

    // Course: Linux Fundamentals
  
    "linux-fundamentals": {
      id: "linux-fundamentals",
      tags: [
        { label: "Fundamental Track", icon: "shield" },
        { label: "Linux Basics", icon: "code" },
        { label: "Command Line", icon: "terminal" }
      ],
      title: "Linux Fundamentals",
      track: "Fundamental Track",
      level: "Beginner",
      duration: "8 Weeks",
      description: "Linux Fundamentals gives you a clear and practical introduction to how modern Linux systems work. You’ll learn the basics of command line usage, users and permissions, processes, services, networking, file systems, storage management, and shell scripting in everyday work use. The course builds your understanding step-by-step so you can see how each layer works together to keep systems and data safe, preparing you for more advanced security learning",
     
      learningObjectives: [
        "Understand Linux architecture and its core components",
        "Navigate the command line and manage files and directories",
        "Configure users, groups, and permissions for secure access",
        "Install and manage software packages across distributions",
        "Monitor processes, services, and system performance effectively",
        "Build confidence to use Linux in security and development workflows"
      ],
   
      prerequisites: [
        "Basic familiarity with computers and file systems",
        "Willingness to learn command-line operations step-by-step",
        "No prior Linux or programming experience is needed",
        "Any machine capable of running Linux or a VM environment"
      ],

      modules: [
          // Chapter 1
          { 
              title: "Chapter 1: Introduction to Linux & Operating Systems", 
              lessons: [
                  { id: "overview-of-operating-systems-linux-vs-windows-vs-macos", title: "Overview of Operating Systems: Linux vs Windows vs macOS", type: "video", duration: "12m 30s", completed: false },
                  { id: "history-of-linux-and-open-source-philosophy", title: "History of Linux and Open Source Philosophy", type: "video", duration: "9m 00s", completed: false },
                  { id: "linux-distributions-ubuntu-centos-debian-fedora", title: "Linux Distributions (Ubuntu, CentOS, Debian, Fedora)", type: "video", duration: "15m 45s", completed: false },
                  { id: "linux-kernel-shell-and-user-interface-concepts", title: "Linux Kernel, Shell, and User Interface Concepts", type: "video", duration: "10m 10s", completed: false },
                  { id: "linux-file-system-overview-ext4-xfs-btrfs", title: "Linux File System Overview (ext4, xfs, btrfs)", type: "video", duration: "14m 20s", completed: false },
                  { id: "boot-process-bios/uefi-grub-init/systemd", title: "Boot Process: BIOS/UEFI, GRUB, init/systemd", type: "video", duration: "18m 00s", completed: false },
                  { id: "lab-exploring-distributions-filesystem-permissions-&-ownership", title: "Lab: Exploring Distributions, Filesystem Permissions & Ownership", type: "video", duration: "35m 00s", completed: false }
              ] 
          },
          // Chapter 2
          { 
              title: "Chapter 2: Linux Command Line Essentials", 
              lessons: [
                  { id: "introduction-to-shell-bash-zsh-and-other-shells", title: "Introduction to Shell: Bash, Zsh, and Other Shells", type: "video", duration: "10m 40s", completed: false },
                  { id: "basic-commands-ls-cd-pwd-cp-mv-rm-touch-cat-echo", title: "Basic Commands: ls, cd, pwd, cp, mv, rm, touch, cat, echo", type: "video", duration: "20m 15s", completed: false },
                  { id: "file-and-directory-management-&-absolute-vs-relative-paths", title: "File and Directory Management & Absolute vs Relative Paths", type: "video", duration: "15m 50s", completed: false },
                  { id: "file-viewing-&-manipulation-less-head-tail-grep", title: "File Viewing & Manipulation: less, head, tail, grep", type: "video", duration: "18m 30s", completed: false },
                  { id: "advanced-search-find-locate-&-command-history-and-shortcuts", title: "Advanced Search: find, locate & Command History and Shortcuts", type: "video", duration: "14m 10s", completed: false },
                  { id: "lab-searching-sensitive-files-with-grep-and-monitoring-logs", title: "Lab: Searching Sensitive Files with Grep and Monitoring Logs", type: "video", duration: "40m 00s", completed: false }
              ]
          },
          // Chapter 3
          { 
              title: "Chapter 3: Users, Groups & Permissions", 
              lessons: [
                  { id: "understanding-users-and-groups-in-linux", title: "Understanding Users and Groups in Linux", type: "video", duration: "12m 55s", completed: false },
                  { id: "managing-users-useradd-usermod-passwd-deluser", title: "Managing Users: useradd, usermod, passwd, deluser", type: "video", duration: "16m 00s", completed: false },
                  { id: "managing-groups-groupadd-groupmod-gpasswd", title: "Managing Groups: groupadd, groupmod, gpasswd", type: "video", duration: "10m 25s", completed: false },
                  { id: "file-permissions-and-ownership-chmod-chown-chgrp", title: "File Permissions and Ownership (chmod, chown, chgrp)", type: "video", duration: "22m 30s", completed: false },
                  { id: "special-permissions-suid-sgid-sticky-bit", title: "Special Permissions: SUID, SGID, Sticky Bit", type: "video", duration: "15m 10s", completed: false },
                  { id: "acls-access-control-lists-for-advanced-permissions", title: "ACLs (Access Control Lists) for Advanced Permissions", type: "video", duration: "18m 40s", completed: false },
                  { id: "lab-secure-user-creation-and-implementing-acls", title: "Lab: Secure User Creation and Implementing ACLs", type: "video", duration: "45m 00s", completed: false }
              ]
          },
          // Chapter 4
          { 
              title: "Chapter 4: Package Management & System Configuration", 
              lessons: [
                  { id: "installing-and-updating-software-packages-apt-yum-dnf-snap", title: "Installing and Updating Software Packages (apt, yum, dnf, snap)", type: "video", duration: "17m 20s", completed: false },
                  { id: "managing-repositories-and-dependencies", title: "Managing Repositories and Dependencies", type: "video", duration: "11m 35s", completed: false },
                  { id: "system-configuration-files-/etc/hosts-/etc/fstab-/etc/passwd", title: "System Configuration Files: /etc/hosts, /etc/fstab, /etc/passwd", type: "video", duration: "19m 10s", completed: false },
                  { id: "environment-variables-and-shell-configuration-.bashrc-.profile", title: "Environment Variables and Shell Configuration (.bashrc, .profile)", type: "video", duration: "14m 50s", completed: false },
                  { id: "lab-reducing-attack-surface-by-removing-packages-and-securing-environment-variables", title: "Lab: Reducing Attack Surface by Removing Packages and Securing Environment Variables", type: "video", duration: "30m 00s", completed: false }
              ]
          },
          // Chapter 5
          { 
              title: "Chapter 5: Process & Service Management", 
              lessons: [
                  { id: "understanding-processes-pid-ppid-foreground-vs-background", title: "Understanding Processes: PID, PPID, foreground vs background", type: "video", duration: "13m 15s", completed: false },
                  { id: "process-monitoring-ps-top-htop-pgrep", title: "Process Monitoring: ps, top, htop, pgrep", type: "video", duration: "16m 40s", completed: false },
                  { id: "process-control-kill-nice-renice-jobs-fg-bg", title: "Process Control: kill, nice, renice, jobs, fg, bg", type: "video", duration: "14m 25s", completed: false },
                  { id: "managing-services-systemctl-service-chkconfig", title: "Managing Services: systemctl, service, chkconfig", type: "video", duration: "20m 05s", completed: false },
                  { id: "scheduled-tasks-cron-at-systemd-timers", title: "Scheduled Tasks: cron, at, systemd timers", type: "video", duration: "17m 55s", completed: false },
                  { id: "lab-monitoring-suspicious-processes-&-scheduling-security-checks-with-cron", title: "Lab: Monitoring Suspicious Processes & Scheduling Security Checks with Cron", type: "video", duration: "35m 00s", completed: false }
              ]
          },
          // Chapter 6
          { 
              title: "Chapter 6: Networking in Linux", 
              lessons: [
                  { id: "network-interfaces-ifconfig-ip-addr-ip-link", title: "Network Interfaces: ifconfig, ip addr, ip link", type: "video", duration: "14m 30s", completed: false },
                  { id: "routing-tables-and-network-configuration-route-netstat-ss", title: "Routing Tables and Network Configuration (route, netstat, ss)", type: "video", duration: "16m 10s", completed: false },
                  { id: "basic-tcp/ip-concepts-on-linux", title: "Basic TCP/IP Concepts on Linux", type: "video", duration: "10m 50s", completed: false },
                  { id: "firewall-basics-iptables-firewalld-ufw", title: "Firewall Basics: iptables, firewalld, ufw", type: "video", duration: "25m 20s", completed: false },
                  { id: "network-diagnostics-ping-traceroute-dig-nslookup-tcpdump", title: "Network Diagnostics: ping, traceroute, dig, nslookup, tcpdump", type: "video", duration: "20m 45s", completed: false },
                  { id: "lab-configuring-firewalls-&-monitoring-traffic-with-tcpdump", title: "Lab: Configuring Firewalls & Monitoring Traffic with tcpdump", type: "video", duration: "40m 00s", completed: false }
              ]
          },
          // Chapter 7
          { 
              title: "Chapter 7: File Systems & Storage Management", 
              lessons: [
                  { id: "linux-filesystem-hierarchy-/etc-/var-/home-/usr", title: "Linux Filesystem Hierarchy (/etc, /var, /home, /usr)", type: "video", duration: "13m 50s", completed: false },
                  { id: "disk-management-fdisk-parted-lsblk-df-du", title: "Disk Management: fdisk, parted, lsblk, df, du", type: "video", duration: "18m 00s", completed: false },
                  { id: "mounting-and-unmounting-file-systems-mount-umount", title: "Mounting and Unmounting File Systems: mount, umount", type: "video", duration: "12m 30s", completed: false },
                  { id: "swap-management-and-disk-quotas", title: "Swap Management and Disk Quotas", type: "video", duration: "15m 05s", completed: false },
                  { id: "understanding-inodes-links-and-symbolic-links", title: "Understanding inodes, links, and symbolic links", type: "video", duration: "10m 40s", completed: false },
                  { id: "lab-auditing-disk-usage-&-implementing-disk-quotas", title: "Lab: Auditing Disk Usage & Implementing Disk Quotas", type: "video", duration: "35m 00s", completed: false }
              ]
          },

          // Chapter 8
          { 
              title: "Chapter 8: Shell Scripting & Automation", 
              lessons: [
                  { id: "bash-scripting-basics-variables-loops-conditionals", title: "Bash Scripting Basics: Variables, Loops, Conditionals", type: "video", duration: "20m 10s", completed: false },
                  { id: "functions-in-scripts-&-input/output-handling", title: "Functions in Scripts & Input/Output Handling", type: "video", duration: "14m 50s", completed: false },
                  { id: "automating-system-administration-tasks", title: "Automating System Administration Tasks", type: "video", duration: "17m 30s", completed: false },
                  { id: "using-scripts-for-log-parsing-alerts-and-monitoring", title: "Using Scripts for Log Parsing, Alerts, and Monitoring", type: "video", duration: "16m 40s", completed: false },
                  { id: "challenge-scripting-automated-security-patching-&-alerting", title: "Challenge: Scripting Automated Security Patching & Alerting", type: "video", duration: "50m 00s", completed: false }
              ]
          },
      ]
    },
    // Course: Programming With Python

    "programming-with-python": {
      id: "programming-with-python",
      tags: [
        { label: "Fundamental Track", icon: "shield" },
        { label: "Python Basics", icon: "code" },
        { label: "Secure Coding", icon: "lock" }
      ],
      title: "Programming with Python: Security Scripting",
      track: "Fundamental Track",
      level: "Beginner",
      duration: "6 Weeks",
      description: "Python Essentials gives you a clear and practical introduction to how modern Python programming works. You’ll learn the basics of variables, data types, strings, lists, loops, functions, file handling, exceptions, OOP, algorithms, and automation through APIs and bash script. The course builds your understanding step-by-step so you can see how each concept works together to create secure, efficient, and reliable Python applications, preparing you for more advanced Python learning.",
      
      learningObjectives: [
        "Learn core Python syntax, variables, and data structures",
        "Write programs using loops, conditions, and functions",
        "Handle files, exceptions, and structured data formats",
        "Work with modules, packages, and reusable code patterns",
        "Build simple automation scripts for security or daily tasks",
        "Develop a strong base for advanced Python development"
      ],
   
      prerequisites: [
        "Basic computer literacy and general problem-solving skills",
        "Understanding of what software applications do at a high level",
        "No prior programming experience is required for beginners",
        "A computer with Python installed or access to an online editor"
      ],

      modules: [
          // Chapter 1
          { 
              title: "Chapter 1: Python Fundamentals", 
              lessons: [
                  { id: "course-introduction-and-overview", title: "Course Introduction and Overview", type: "video", duration: "8m 00s", completed: false },
                  { id: "python-vs-other-languages-benefits-and-applications", title: "Python vs. Other Languages: Benefits and Applications", type: "video", duration: "10m 30s", completed: false },
                  { id: "technical-overview-interpreter-vs-compiler-&-setup", title: "Technical Overview: Interpreter vs Compiler & Setup", type: "video", duration: "15m 15s", completed: false },
                  { id: "variables-data-types-and-type-conversion", title: "Variables, Data Types, and Type Conversion", type: "video", duration: "12m 40s", completed: false },
                  { id: "strings-creation-formatting-built-in-methods", title: "Strings: Creation, Formatting, Built-in Methods", type: "video", duration: "16m 50s", completed: false },
                  { id: "indexing-slicing-lists-and-basic-operations", title: "Indexing, Slicing, Lists, and Basic Operations", type: "video", duration: "20m 00s", completed: false },
                  { id: "control-flow-conditional-statements-and-loops", title: "Control Flow: Conditional Statements and Loops", type: "video", duration: "14m 25s", completed: false },
                  { id: "lab-input-validation-password-strength-check-and-string-parsing", title: "Lab: Input Validation, Password Strength Check, and String Parsing", type: "video", duration: "45m 00s", completed: false }
              ] 
          },
          // Chapter 2
          { 
              title: "Chapter 2: Intermediate Python", 
              lessons: [
                  { id: "for-and-while-loops-advanced-usage-and-nesting", title: "For and While Loops: Advanced Usage and Nesting", type: "video", duration: "15m 30s", completed: false },
                  { id: "tuples-sets-and-dictionaries-operations-and-iteration", title: "Tuples, Sets, and Dictionaries: Operations and Iteration", type: "video", duration: "18m 10s", completed: false },
                  { id: "nested-data-structures-and-traversal-patterns", title: "Nested Data Structures and Traversal Patterns", type: "video", duration: "14m 00s", completed: false },
                  { id: "user-input-handling-and-validation", title: "User Input Handling and Validation", type: "video", duration: "11m 45s", completed: false },
                  { id: "functions-definition-arguments-return-values", title: "Functions: Definition, Arguments, Return Values", type: "video", duration: "16m 20s", completed: false },
                  { id: "variable-arguments-*args-and-**kwargs-and-lambda-functions", title: "Variable Arguments (*args and **kwargs) and Lambda Functions", type: "video", duration: "13m 50s", completed: false },
                  { id: "modular-programming-modules-packages-and-main-entry-point", title: "Modular Programming: Modules, Packages, and Main Entry Point", type: "video", duration: "15m 05s", completed: false },
                  { id: "lab-building-a-cli-utility-for-log-sanitation-and-input-validation", title: "Lab: Building a CLI Utility for Log Sanitation and Input Validation", type: "video", duration: "40m 00s", completed: false }
              ]
          },
          // Chapter 3
          { 
              title: "Chapter 3: File Handling & Exception Management", 
              lessons: [
                  { id: "file-i/o-reading-writing-and-context-managers", title: "File I/O: Reading, Writing, and Context Managers", type: "video", duration: "14m 40s", completed: false },
                  { id: "text-and-binary-file-operations", title: "Text and Binary File Operations", type: "video", duration: "10m 25s", completed: false },
                  { id: "csv-and-json-file-handling", title: "CSV and JSON File Handling", type: "video", duration: "16m 55s", completed: false },
                  { id: "exception-handling-try/except/else/finally", title: "Exception Handling: try/except/else/finally", type: "video", duration: "18m 30s", completed: false },
                  { id: "custom-exceptions-and-raising-errors", title: "Custom Exceptions and Raising Errors", type: "video", duration: "11m 15s", completed: false },
                  { id: "best-practices-for-robust-safe-file-handling", title: "Best Practices for Robust, Safe File Handling", type: "video", duration: "10m 40s", completed: false },
                  { id: "lab-secure-log-parsing-exception-handling-and-data-sanitization", title: "Lab: Secure Log Parsing, Exception Handling, and Data Sanitization", type: "video", duration: "45m 00s", completed: false }
              ]
          },
          // Chapter 4
          { 
              title: "Chapter 4: Object-Oriented Programming (OOP)", 
              lessons: [
                  { id: "introduction-to-classes-and-objects", title: "Introduction to Classes and Objects", type: "video", duration: "15m 50s", completed: false },
                  { id: "attributes-methods-and-constructors-__init__", title: "Attributes, Methods, and Constructors (__init__)", type: "video", duration: "13m 10s", completed: false },
                  { id: "encapsulation-inheritance-and-polymorphism", title: "Encapsulation, Inheritance, and Polymorphism", type: "video", duration: "20m 00s", completed: false },
                  { id: "class-vs-instance-attributes-&-advanced-class-techniques", title: "Class vs Instance Attributes & Advanced Class Techniques", type: "video", duration: "14m 20s", completed: false },
                  { id: "design-patterns-factory-singleton-adapter-strategy", title: "Design Patterns: Factory, Singleton, Adapter, Strategy", type: "video", duration: "17m 45s", completed: false },
                  { id: "organizing-packages-and-modules-for-large-projects", title: "Organizing Packages and Modules for Large Projects", type: "video", duration: "12m 30s", completed: false },
                  { id: "real-world-case-studies-using-oop", title: "Real-World Case Studies Using OOP", type: "video", duration: "10m 10s", completed: false },
                  { id: "lab-implementing-secure-credential-management-classes-and-event-logging", title: "Lab: Implementing Secure Credential Management Classes and Event Logging", type: "video", duration: "50m 00s", completed: false }
              ]
          },
          // Chapter 5
          { 
              title: "Chapter 5: Algorithms, Complexity & Optimization", 
              lessons: [
                  { id: "algorithm-design-principles-and-problem-decomposition", title: "Algorithm Design Principles and Problem Decomposition", type: "video", duration: "13m 45s", completed: false },
                  { id: "time-complexity-big-o-and-space-complexity", title: "Time Complexity (Big O) and Space Complexity", type: "video", duration: "18m 20s", completed: false },
                  { id: "recursion-and-iteration-techniques", title: "Recursion and Iteration Techniques", type: "video", duration: "11m 55s", completed: false },
                  { id: "sorting-searching-and-traversal-algorithms", title: "Sorting, Searching, and Traversal Algorithms", type: "video", duration: "19m 30s", completed: false },
                  { id: "code-optimization-efficient-data-structures-and-memoization", title: "Code Optimization: Efficient Data Structures and Memoization", type: "video", duration: "15m 10s", completed: false },
                  { id: "profiling-and-benchmarking-timeit-cprofile", title: "Profiling and Benchmarking (timeit, cProfile)", type: "video", duration: "10m 00s", completed: false },
                  { id: "lab-optimizing-scripts-for-anomaly-detection-and-preventing-memory-attacks", title: "Lab: Optimizing Scripts for Anomaly Detection and Preventing Memory Attacks", type: "video", duration: "40m 00s", completed: false }
              ]
          },
          // Chapter 6
          { 
              title: "Chapter 6: Working with APIs & Automation", 
              lessons: [
                  { id: "introduction-to-apis-rest-vs-graphql-request-response-model", title: "Introduction to APIs: REST vs GraphQL, Request-Response Model", type: "video", duration: "14m 10s", completed: false },
                  { id: "making-http-requests-using-requests-and-httpx-libraries", title: "Making HTTP Requests using requests and httpx Libraries", type: "video", duration: "16m 25s", completed: false },
                  { id: "handling-json/xml-responses-parsing-and-validation", title: "Handling JSON/XML Responses, Parsing, and Validation", type: "video", duration: "12m 50s", completed: false },
                  { id: "authentication-&-authorization-api-keys-oauth2-jwt-tokens", title: "Authentication & Authorization: API keys, OAuth2, JWT tokens", type: "video", duration: "18m 00s", completed: false },
                  { id: "rate-limiting-error-handling-and-retry-mechanisms", title: "Rate-limiting, Error Handling, and Retry Mechanisms", type: "video", duration: "11m 40s", completed: false },
                  { id: "automating-tasks-fetching-logs-monitoring-triggering-alerts", title: "Automating Tasks: Fetching Logs, Monitoring, Triggering Alerts", type: "video", duration: "15m 15s", completed: false },
                  { id: "security-considerations-input-validation-secure-storage-of-credentials", title: "Security Considerations: Input Validation, Secure Storage of Credentials", type: "video", duration: "13m 30s", completed: false },
                  { id: "lab-building-a-security-alert-system-and-securely-managing-api-secrets", title: "Lab: Building a Security Alert System and Securely Managing API Secrets", type: "video", duration: "55m 00s", completed: false }
              ]
          },
      ]
    },

////////////////////////////////////////////////////////////////////////////////
////////////////////////////////////////////////////////////////////////////////
// -----------------------Track 1: Web Security & VAPT-------------------------
////////////////////////////////////////////////////////////////////////////////
////////////////////////////////////////////////////////////////////////////////

  // Course: Web Development Fundamentals

  "web-development-fundamentals": {
        id: "web-development-fundamentals",
        tags: [
            { label: "Specialization Track", icon: "shield" },
            { label: "Web Development", icon: "code" },
            { label: "APIs", icon: "database" }
          ],
        title: "Web Development Fundamentals",
        track: "Web Security Track",
        level: "Beginner",
        duration: "6 Weeks",
        description: "Web Development Essentials gives you a clear and practical introduction to how modern web applications work. You’ll learn the basics of HTML, CSS, JavaScript, React, backend frameworks, APIs, database, authentication, and key security practices used in full-stack development. The course builds your understanding step-by-step so you can see how each layer works together to keep systems and data safe, preparing you for more advanced security learning.",
        
        learningObjectives: [
            "Understand how the web works through HTTP, browsers, and client-server architecture",
            "Build responsive webpages using HTML, CSS, and modern layout techniques",
            "Use JavaScript to create interactive and dynamic user experiences",
            "Work with APIs to fetch, process, and display external data",
            "Develop modular front-end applications using React fundamentals",
            "Gain the foundation needed to move into backend or full-stack development"
        ],
       
        prerequisites: [
            "Basic computer and internet browsing skills",
            "General understanding of how websites appear and function",
            "No prior coding or design experience is required",
            "A computer with any modern browser and stable internet access"
        ],


        modules: [
            // Chapter 1
            { 
                title: "Module 1: Web Foundations and Front-End Architecture", 
                lessons: [
                    { id: "internet-fundamentals-and-client-server-communication", title: "Internet fundamentals and client-server communication model", type: "video", duration: "10m", completed: false },
                    { id: "http-https-and-the-request-response-lifecycle", title: "HTTP, HTTPS, and the request–response lifecycle", type: "video", duration: "12m", completed: false },
                    { id: "web-architecture-frontend-backend-and-databases", title: "Web architecture: frontend, backend, and databases", type: "video", duration: "8m", completed: false },
                    { id: "html5-structure-and-semantic-design-principles", title: "HTML5 structure and semantic design principles", type: "video", duration: "15m", completed: false },
                    { id: "css3-styling-layout-mechanisms-and-responsive-design", title: "CSS3 styling, layout mechanisms, and responsive design (Flexbox & Grid)", type: "video", duration: "25m", completed: false },
                    { id: "web-accessibility-and-cross-browser-compatibility", title: "Web accessibility (WCAG guidelines) and cross-browser compatibility", type: "video", duration: "10m", completed: false },
                    { id: "version-control-using-git-and-github", title: "Version control using Git and GitHub: branching, merging, and conflict resolution", type: "video", duration: "20m", completed: false },
                    { id: "practical-exercise-deploy-a-responsive-website", title: "Practical Exercise: Deploy a Responsive Website", type: "video", duration: "45m", completed: false },
                ] 
            },
            // Chapter 2
            { 
                title: "Module 2: JavaScript for Interactive Web Applications", 
                lessons: [
                    { id: "javascript-syntax-data-types-functions-and-scope", title: "JavaScript syntax, data types, functions, and scope", type: "video", duration: "18m", completed: false },
                    { id: "dom-manipulation-event-handling-and-user-interaction", title: "DOM manipulation, event handling, and user interaction", type: "video", duration: "22m", completed: false },
                    { id: "asynchronous-programming-callbacks-promises-and-async-await", title: "Asynchronous programming: callbacks, promises, and async/await", type: "video", duration: "15m", completed: false },
                    { id: "fetch-api-for-restful-communication", title: "Fetch API for RESTful communication", type: "video", duration: "10m", completed: false },
                    { id: "es6-features-modules-arrow-functions-template-literals", title: "ES6 features: modules, arrow functions, template literals, destructuring", type: "video", duration: "20m", completed: false },
                    { id: "client-side-data-management-local-and-session-storage", title: "Client-side data management: local and session storage", type: "video", duration: "8m", completed: false },
                    { id: "introduction-to-web-security-from-a-frontend-perspective", title: "Introduction to web security from a frontend perspective (basic input validation)", type: "video", duration: "12m", completed: false },
                    { id: "practical-exercise-implement-live-form-validation", title: "Practical Exercise: Implement Live Form Validation", type: "video", duration: "35m", completed: false },
                ]
            },
            // Chapter 3
            { 
                title: "Module 3: Modern Front-End Development with React", 
                lessons: [
                    { id: "react-architecture-and-component-driven-design", title: "React architecture and component-driven design", type: "video", duration: "15m", completed: false },
                    { id: "jsx-syntax-and-virtual-dom-principles", title: "JSX syntax and virtual DOM principles", type: "video", duration: "10m", completed: false },
                    { id: "props-state-and-component-lifecycle-management", title: "Props, state, and component lifecycle management", type: "video", duration: "25m", completed: false },
                    { id: "react-hooks-usestate-useeffect-usecontext", title: "React Hooks (useState, useEffect, useContext)", type: "video", duration: "20m", completed: false },
                    { id: "routing-using-react-router-v6", title: "Routing using React Router v6", type: "video", duration: "12m", completed: false },
                    { id: "data-fetching-and-api-integration-using-axios", title: "Data fetching and API integration using Axios", type: "video", duration: "18m", completed: false },
                    { id: "context-api-and-application-level-state-management", title: "Context API and application-level state management", type: "video", duration: "14m", completed: false },
                    { id: "performance-optimization-and-lazy-loading", title: "Performance optimization and lazy loading", type: "video", duration: "10m", completed: false },
                    { id: "practical-exercise-develop-a-single-page-react-application", title: "Practical Exercise: Develop a Single-Page React Application", type: "video", duration: "50m", completed: false },
                ]
            },
            // Chapter 4
            { 
                title: "Module 4: Backend Development with Flask", 
                lessons: [
                    { id: "introduction-to-flask-microframework", title: "Introduction to Flask microframework", type: "video", duration: "10m", completed: false },
                    { id: "application-structure-and-routing-mechanisms", title: "Application structure and routing mechanisms", type: "video", duration: "15m", completed: false },
                    { id: "request-and-response-handling-get-post-put-delete", title: "Request and response handling (GET, POST, PUT, DELETE)", type: "video", duration: "18m", completed: false },
                    { id: "jinja2-templating-and-dynamic-page-rendering", title: "Jinja2 templating and dynamic page rendering", type: "video", duration: "12m", completed: false },
                    { id: "rest-api-design-and-implementation", title: "REST API design and implementation", type: "video", duration: "20m", completed: false },
                    { id: "database-integration-with-sqlalchemy-orm", title: "Database integration with SQLAlchemy ORM", type: "video", duration: "25m", completed: false },
                    { id: "authentication-and-authorization-sessions-jwt", title: "Authentication and authorization (sessions, JWT)", type: "video", duration: "15m", completed: false },
                    { id: "input-validation-and-secure-form-handling", title: "Input validation and secure form handling", type: "video", duration: "10m", completed: false },
                    { id: "exception-handling-logging-and-middleware-integration", title: "Exception handling, logging, and middleware integration", type: "video", duration: "12m", completed: false },
                    { id: "practical-exercise-build-a-restful-api-with-flask", title: "Practical Exercise: Build a RESTful API with Flask", type: "video", duration: "40m", completed: false },
                ]
            },
            // Chapter 5
            { 
                title: "Module 5: Advanced Backend Development with Django", 
                lessons: [
                    { id: "django-architecture-and-project-structure", title: "Django architecture and project structure", type: "video", duration: "18m", completed: false },
                    { id: "url-routing-views-and-template-rendering", title: "URL routing, views, and template rendering", type: "video", duration: "15m", completed: false },
                    { id: "model-creation-orm-queries-and-migrations", title: "Model creation, ORM queries, and migrations", type: "video", duration: "22m", completed: false },
                    { id: "form-handling-and-validation", title: "Form handling and validation", type: "video", duration: "10m", completed: false },
                    { id: "django-authentication-and-permission-management", title: "Django authentication and permission management", type: "video", duration: "15m", completed: false },
                    { id: "admin-interface-customization", title: "Admin interface customization", type: "video", duration: "8m", completed: false },
                    { id: "django-rest-framework-drf-for-api-creation", title: "Django REST Framework (DRF) for API creation", type: "video", duration: "25m", completed: false },
                    { id: "database-design-and-optimization", title: "Database design and optimization (PostgreSQL integration)", type: "video", duration: "12m", completed: false },
                    { id: "secure-coding-prevention-of-xss-csrf-and-sql-injection-attacks", title: "Secure coding: prevention of XSS, CSRF, and SQL injection attacks", type: "video", duration: "20m", completed: false },
                    { id: "practical-exercise-create-secure-restful-apis-using-django-rest-framework", title: "Practical Exercise: Create Secure RESTful APIs using Django REST Framework", type: "video", duration: "55m", completed: false },
                ]
            },
            // Chapter 6
            { 
                title: "Module 6: Advanced Web Technologies and Security Integration", 
                lessons: [
                    { id: "rest-vs-graphql-architectures-and-api-design-principles", title: "REST vs. GraphQL architectures and API design principles", type: "video", duration: "15m", completed: false },
                    { id: "api-security-mechanisms-jwt-oauth2-and-api-keys", title: "API security mechanisms: JWT, OAuth2, and API keys", type: "video", duration: "20m", completed: false },
                    { id: "cors-management-and-http-security-headers", title: "CORS management and HTTP security headers", type: "video", duration: "10m", completed: false },
                    { id: "rate-limiting-request-throttling-and-data-validation", title: "Rate limiting, request throttling, and data validation", type: "video", duration: "18m", completed: false },
                    { id: "secure-data-transmission-using-https-and-ssl-tls", title: "Secure data transmission using HTTPS and SSL/TLS", type: "video", duration: "12m", completed: false },
                    { id: "secure-development-life-cycle-sdlc-and-owasp-top-10-practices", title: "Secure development life cycle (SDLC) and OWASP Top 10 practices", type: "video", duration: "25m", completed: false },
                    { id: "application-level-firewalls-and-intrusion-prevention-concepts", title: "Application-level firewalls and intrusion prevention concepts", type: "video", duration: "15m", completed: false },
                    { id: "practical-exercise-implement-rate-limiting-and-request-validation", title: "Practical Exercise: Implement rate limiting and request validation", type: "video", duration: "40m", completed: false },
                ]
            },
        ]
    },

    // Course: Web Security & VAPT
    "web-security-vapt-core": {
        id: "web-security-vapt-core",
        tags: [
            { label: "Specialization Track", icon: "shield" },
            { label: "Web Security", icon: "code" },
            { label: "Bug Hunting", icon: "bug" }
          ],
        title: "Web Security & VAPT",
        track: "Web Security Track",
        level: "Intermediate to Expert",
        duration: "11 Weeks",
        description: "Web Security Essentials gives you a clear and practical introduction to how modern web vulnerabilities work. You’ll learn the basics of recon, scanning, file upload vulnerability, XSS, CSRF, SSRF, IDOR, information disclosure, SQL injection, API flaw, and logic vulnerability. The course builds your understanding step-by-step so you can see how each layer works together to keep systems and data safe, preparing you for more advanced security learning.",
        
        learningObjectives: [
            "Understand core security concepts and how attackers target web applications",
            "Identify and exploit common vulnerabilities such as XSS, CSRF, and SQLi",
            "Perform structured reconnaissance and enumeration on web targets",
            "Use industry tools to analyze, test, and validate security issues",
            "Write clear vulnerability reports with impact, steps, and remediation",
            "Build the essential skill set required for bug bounty and VAPT roles"
        ],
       
        prerequisites: [
            "Basic understanding of how websites and web requests work",
            "Comfort using a browser, simple tools, and navigating online platforms",
            "No prior cybersecurity or programming background required",
            "A Windows, Mac, or Linux system capable of running testing tools"
        ],

        modules: [
            // Chapter 1 
            { 
                title: "Module 1: Reconnaissance and Scanning", 
                lessons: [
                    { id: "recon-passive-active-osint", title: "Types of reconnaissance: passive and active (OSINT)", type: "video", duration: "15m", completed: false },
                    { id: "subdomain-enumeration-and-asset-discovery", title: "Subdomain enumeration and asset discovery", type: "video", duration: "18m", completed: false },
                    { id: "banner-grabbing-and-service-identification", title: "Banner grabbing and service identification", type: "video", duration: "10m", completed: false },
                ] 
            },
            // Chapter 2
            { 
                title: "Module 2: File Upload Vulnerabilities", 
                lessons: [
                    { id: "file-upload-mechanisms-and-security-risks", title: "Understanding file upload mechanisms and security risks", type: "video", duration: "12m", completed: false },
                    { id: "exploiting-mime-type-verification-and-bypass", title: "MIME type verification and bypass techniques", type: "video", duration: "20m", completed: false },
                    { id: "secure-file-upload-handling-and-mitigation", title: "Secure file upload handling and server-side mitigation", type: "video", duration: "15m", completed: false },
                ]
            },
            // Chapter 3
            { 
                title: "Module 3: Cross-Site Scripting (XSS)", 
                lessons: [
                    { id: "reflected-stored-and-dom-based-xss", title: "Understanding reflected, stored, and DOM-based XSS", type: "video", duration: "25m", completed: false },
                    { id: "payload-development-and-filter-bypassing", title: "Payload development and filter bypassing", type: "video", duration: "18m", completed: false },
                    { id: "security-controls-and-xss-mitigation", title: "Security controls and mitigation best practices", type: "video", duration: "10m", completed: false },
                ]
            },
            // Chapter 4
            { 
                title: "Module 4: CSRF and SSRF Vulnerabilities", 
                lessons: [
                    { id: "understanding-cross-site-request-forgery-csrf", title: "Understanding Cross-Site Request Forgery (CSRF) attacks", type: "video", duration: "15m", completed: false },
                    { id: "introduction-to-server-side-request-forgery-ssrf", title: "Introduction to Server-Side Request Forgery (SSRF)", type: "video", duration: "22m", completed: false },
                    { id: "mitigation-through-input-validation-and-segmentation", title: "Mitigation through input validation and network segmentation", type: "video", duration: "12m", completed: false },
                ]
            },
            // Chapter 5
            { 
                title: "Module 5: CORS Misconfiguration", 
                lessons: [
                    { id: "introduction-to-cors-and-preflight-requests", title: "Introduction to Cross-Origin Resource Sharing (CORS)", type: "video", duration: "10m", completed: false },
                    { id: "common-misconfigurations-and-data-stealing", title: "Common misconfigurations and stealing sensitive data", type: "video", duration: "18m", completed: false },
                    { id: "secure-configuration-practices-and-validation", title: "Secure configuration practices and validation rules", type: "video", duration: "10m", completed: false },
                ]
            },
            // Chapter 6
            { 
                title: "Module 6: Insecure Direct Object References (IDOR)", 
                lessons: [
                    { id: "overview-of-idor-and-access-control-bypass", title: "Overview of IDOR and access control bypass", type: "video", duration: "15m", completed: false },
                    { id: "authorization-logic-flaws-and-privilege-escalation", title: "Authorization logic flaws and privilege escalation", type: "video", duration: "20m", completed: false },
                    { id: "prevention-using-rbac-and-object-mapping", title: "Prevention using RBAC and object mapping", type: "video", duration: "12m", completed: false },
                ]
            },
            // Chapter 7
            { 
                title: "Module 7: Broken Authentication and Session Management", 
                lessons: [
                    { id: "weak-session-handling-and-credential-stuffing", title: "Weak session handling and credential stuffing", type: "video", duration: "18m", completed: false },
                    { id: "securing-cookies-and-authentication-tokens-mfa", title: "Securing cookies, tokens, and implementing MFA", type: "video", duration: "22m", completed: false },
                ]
            },
            // Chapter 8
            { 
                title: "Module 8: Information Disclosure", 
                lessons: [
                    { id: "sensitive-data-leaks-through-error-messages", title: "Identifying sensitive data leaks through error messages", type: "video", duration: "10m", completed: false },
                    { id: "misconfigured-web-servers-and-directory-listings", title: "Misconfigured web servers and directory listings", type: "video", duration: "15m", completed: false },
                    { id: "proper-error-handling-and-sanitization", title: "Implementing proper error handling and sanitization", type: "video", duration: "8m", completed: false },
                ]
            },
            // Chapter 9
            { 
                title: "Module 9: SQL Injection", 
                lessons: [
                    { id: "error-based-union-based-and-blind-sqli-exploitation", title: "Error-based, union-based, and blind SQLi exploitation", type: "video", duration: "25m", completed: false },
                    { id: "preventing-sql-injection-using-parameterized-queries", title: "Preventing SQL injection using parameterized queries", type: "video", duration: "15m", completed: false },
                ]
            },
            // Chapter 10
            { 
                title: "Module 10: API and Server-Side Vulnerabilities", 
                lessons: [
                    { id: "common-api-flaws-bola-rate-limiting-and-mass-assignment", title: "Common API flaws: BOLA, rate limiting, and mass assignment", type: "video", duration: "20m", completed: false },
                    { id: "server-side-template-injection-rce", title: "Server-side template injection (SSTI) and RCE", type: "video", duration: "18m", completed: false },
                    { id: "secure-api-design-and-scopes", title: "Secure API design, authentication, and scopes", type: "video", duration: "12m", completed: false },
                ]
            },
            // Chapter 11
            { 
                title: "Module 11: Web Cache and Logic Flaws", 
                lessons: [
                    { id: "exploiting-web-cache-poisoning", title: "Exploiting web cache poisoning", type: "video", duration: "15m", completed: false },
                    { id: "business-logic-vulnerability-identification", title: "Business logic vulnerability identification", type: "video", duration: "10m", completed: false },
                ]
            }
        ]
    },
////////////////////////////////////////////////////////////////////////////////
////////////////////////////////////////////////////////////////////////////////
// --------------Track 2: Blockchain & Smart Contracts Security-----------------
////////////////////////////////////////////////////////////////////////////////
////////////////////////////////////////////////////////////////////////////////

// Course: Blockchain & Defi Fundamentals

  "blockchain-defi-fundamentals": {
        
        id: "blockchain-defi-fundamentals",
        tags: [
            { label: "Specialization Track", icon: "shield" },
            { label: "Blockchain Basics", icon: "code" },
            { label: "Crypto Tech", icon: "lock-closed" },
          ],
        title: "Blockchain & DeFi Fundamentals",
        track: "Blockchain & Smart Contract Security",
        level: "Beginner",
        duration: "4 Weeks",
        description: "Blockchain Essentials gives you a clear and practical introduction to how modern blockchain systems work. You’ll learn the basics of blockchain concepts, smart contracts, tokens, wallets, DeFi, DAOs, scalability, interoperability, and security topics covering core topics use. The course builds your understanding step-by-step so you can see how each layer works together to keep systems and data safe, preparing you for more advanced security learning.",
        
        learningObjectives: [
            "Understand blockchain fundamentals including decentralization and consensus",
            "Explore how cryptocurrencies work and what makes them secure",
            "Learn the role of wallets, keys, addresses, and transaction flow",
            "Study major token standards and how digital assets are created",
            "Understand the core building blocks behind DeFi platforms and protocols",
            "Gain a clear foundation to move into smart contracts and blockchain development"
        ],
       
        prerequisites: [
            "Basic understanding of blockchain concepts or willingness to learn them",
            "Comfort using a computer and running development tools",
            "No prior programming in Solidity is required",
            "A laptop capable of running Node.js, Foundry, and coding environments"
        ],

        modules: [
            // Chapter 1
            {
                title: "Module 1: Introduction to Blockchain",
                lessons: [
                    { id: "what-is-blockchain-core-concepts", title: "What is Blockchain? Key properties: immutability, transparency, decentralization", type: "video", duration: "15m", completed: false },
                    { id: "history-and-evolution-of-blockchain", title: "History and evolution of blockchain technology", type: "video", duration: "12m", completed: false },
                    { id: "fundamentals-consensus-ledger-dlt", title: "Fundamentals: Consensus, Distributed Ledger Technology (DLT)", type: "video", duration: "18m", completed: false },
                    { id: "cryptography-hashing-digital-signatures", title: "Cryptographic algorithms: Hashing and Digital Signatures", type: "video", duration: "20m", completed: false },
                    { id: "genesis-block-and-network-types", title: "The Genesis Block & Types of Blockchain (Public, Private, Consortium)", type: "video", duration: "15m", completed: false }
                ]
            },
            // Chapter 2
            {
                title: "Module 2: Blockchain Architecture & Smart Contracts",
                lessons: [
                    { id: "blockchain-components-blocks-nodes", title: "Blockchain Components: Blocks, Nodes, Transactions, Ledger", type: "video", duration: "15m", completed: false },
                    { id: "understanding-blockchain-architecture", title: "Understanding the Blockchain Architecture", type: "video", duration: "18m", completed: false },
                    { id: "introduction-to-smart-contracts-evm", title: "Introduction to Smart Contracts & Ethereum Virtual Machine (EVM)", type: "video", duration: "20m", completed: false },
                    { id: "smart-contract-execution-flow", title: "How Smart Contracts Execute on Blockchain", type: "video", duration: "15m", completed: false },
                    { id: "smart-contract-use-cases-and-security", title: "Use Cases and Security Considerations in Design", type: "video", duration: "12m", completed: false }
                ]
            },
            // Chapter 3
            {
                title: "Module 3: Cryptocurrency & Crypto Wallets",
                lessons: [
                    { id: "blockchain-vs-cryptocurrency", title: "Difference between Blockchain and Cryptocurrency", type: "video", duration: "10m", completed: false },
                    { id: "popular-cryptocurrencies-btc-eth", title: "Introduction to Popular Cryptocurrencies (Bitcoin, Ethereum)", type: "video", duration: "12m", completed: false },
                    { id: "crypto-wallet-types-security", title: "Crypto Wallets: Types (Hot, Cold, Hardware) & Security Best Practices", type: "video", duration: "20m", completed: false },
                    { id: "addresses-keys-transactions", title: "Wallet Addresses, Keys, and Transaction Lifecycle", type: "video", duration: "18m", completed: false }
                ]
            },
            // Chapter 4
            {
                title: "Module 4: Blockchain Tokens & Standards",
                lessons: [
                    { id: "introduction-to-tokens-utility-security", title: "Introduction to Tokens: Utility, Security, Governance", type: "video", duration: "15m", completed: false },
                    { id: "token-standards-erc20-erc721-erc1155", title: "Token Standards: ERC-20, ERC-721, ERC-1155", type: "video", duration: "22m", completed: false },
                    { id: "token-creation-issuance-management", title: "Token Creation, Issuance, and Decentralized Management", type: "video", duration: "18m", completed: false },
                    { id: "tokenomics-and-economic-models", title: "Tokenomics and Interest Models in Blockchain", type: "video", duration: "15m", completed: false }
                ]
            },
            // Chapter 5
            {
                title: "Module 5: Decentralized Finance (DeFi)",
                lessons: [
                    { id: "defi-introduction-significance", title: "Introduction to DeFi and its Significance", type: "video", duration: "15m", completed: false },
                    { id: "defi-building-blocks-lending-amm", title: "Building Blocks: Lending, Borrowing, Liquidity Pools, Yield Farming", type: "video", duration: "25m", completed: false },
                    { id: "defi-protocols-and-platforms", title: "Overview of Major DeFi Protocols and Platforms", type: "video", duration: "20m", completed: false },
                    { id: "defi-risks-security-tokenomics", title: "Risks, Security Considerations, and Incentives in DeFi", type: "video", duration: "18m", completed: false }
                ]
            },
            // Chapter 6
            {
                title: "Module 6: Decentralized Autonomous Organizations (DAOs)",
                lessons: [
                    { id: "dao-purpose-structure-governance", title: "What are DAOs? Purpose, Structure, and Governance", type: "video", duration: "15m", completed: false },
                    { id: "voting-mechanisms-decision-making", title: "Voting Mechanisms and Decision Making", type: "video", duration: "15m", completed: false },
                    { id: "smart-contracts-in-daos", title: "Interaction between DAOs and Smart Contracts", type: "video", duration: "12m", completed: false },
                    { id: "dao-use-cases-security-challenges", title: "Real-world DAO Use Cases and Security Challenges", type: "video", duration: "15m", completed: false }
                ]
            },
            // Chapter 7
            {
                title: "Module 7: Scalability, Interoperability & Security",
                lessons: [
                    { id: "scalability-challenges-layer1-layer2", title: "Scalability Challenges: Layer 1 vs Layer 2 Mechanisms", type: "video", duration: "20m", completed: false },
                    { id: "interoperability-cross-chain", title: "Blockchain Interoperability and Cross-chain Communication", type: "video", duration: "15m", completed: false },
                    { id: "network-security-principles", title: "Security Principles in Blockchain Networks", type: "video", duration: "12m", completed: false },
                    { id: "attack-vectors-mitigation", title: "Common Attack Vectors and Mitigation Strategies", type: "video", duration: "18m", completed: false }
                ]
            }
        ]
    },


    
    // Course: SOLIDITY DEVELOPMENT

    "solidity-smart-contract-development": {
        id: "solidity-smart-contract-development",
        
        tags: [
            { label: "Specialization Track", icon: "shield" },
            { label: "Solidity", icon: "code" },
            { label: "EVM Development", icon: "terminal" },
        ],

        title: "Introduction to Solidity & Smart Contract Development",
        track: "Blockchain & Smart Contract Security",
        level: "Intermediate",
        duration: "6 Weeks",
        description: "Solidity Essentials gives you a clear and practical introduction to how modern smart contract development works. You’ll learn the basics of Solidity syntax, contract structure, storage, data types, DeFi logic, security issues, upgrade patterns, testing, and deployment tasks. aThe course builds your understanding step-by-step so you can see how each layer works together to keep systems and data safe, preparing you for more advanced security learning.",
        
        learningObjectives: [
            "Understand the fundamentals of Ethereum and how smart contracts operate",
            "Learn Solidity syntax, variables, functions, and essential building blocks",
            "Work with data structures such as arrays, mappings, structs, and enums",
            "Use Foundry to test, debug, and deploy smart contracts efficiently",
            "Build DeFi-inspired components such as tokens, pools, and staking logic",
            "Develop a strong foundation to advance into secure smart contract design"
        ],
       
        prerequisites: [
            "Basic understanding of blockchain concepts or willingness to learn them",
            "Comfort using a computer and running development tools",
            "No prior programming in Solidity is required",
            "A laptop capable of running Node.js, Foundry, and coding environments"
        ],

        modules: [
                // Chapter 1
                {
                    title: "Module 1: Introduction to Solidity & Smart Contracts",
                    lessons: [
                        { id: "ethereum-overview-and-smart-contract-use-cases", title: "Overview of Ethereum and Smart Contract Use Cases", type: "video", duration: "15m", completed: false },
                        { id: "solidity-basics-syntax-types-variables", title: "Solidity Basics: Syntax, Types, and Variables", type: "video", duration: "20m", completed: false },
                        { id: "contract-structure-state-variables-functions", title: "Contract Structure: State Variables and Functions", type: "video", duration: "18m", completed: false },
                        { id: "data-types-integers-strings-booleans-mappings", title: "Data Types: Integers, Strings, Arrays, and Mappings", type: "video", duration: "25m", completed: false },
                        { id: "foundry-framework-setup-and-project-structure", title: "Foundry Framework Setup and Project Structure", type: "video", duration: "20m", completed: false }
                    ]
                },
                // Chapter 2
                {
                    title: "Module 2: Solidity Control Structures & Functions",
                    lessons: [
                        { id: "conditional-statements-and-loops", title: "Control Structures: If-Else, Ternary, and Loops", type: "video", duration: "18m", completed: false },
                        { id: "function-definitions-modifiers-visibility", title: "Functions: Visibility (public/private/external) and Modifiers", type: "video", duration: "22m", completed: false },
                        { id: "return-values-and-multiple-outputs", title: "Handling Return Values and Multiple Outputs", type: "video", duration: "12m", completed: false },
                        { id: "testing-basic-functions-using-foundry", title: "Practical: Testing Basic Functions using Foundry", type: "video", duration: "30m", completed: false }
                    ]
                },
                // Chapter 3
                {
                    title: "Module 3: Data Structures & Storage Patterns",
                    lessons: [
                        { id: "structs-and-enums-in-contracts", title: "Organizing Data with Structs and Enums", type: "video", duration: "15m", completed: false },
                        { id: "nested-data-structures-and-mappings", title: "Complex Storage: Nested Mappings and Arrays", type: "video", duration: "20m", completed: false },
                        { id: "storage-vs-memory-variables", title: "Critical Concept: Storage vs Memory vs Calldata", type: "video", duration: "18m", completed: false },
                        { id: "dynamic-data-handling-and-debugging", title: "Dynamic Data Handling and Debugging Storage in Foundry", type: "video", duration: "25m", completed: false }
                    ]
                },
                // Chapter 4
                {
                    title: "Module 4: DeFi Fundamentals in Solidity",
                    lessons: [
                        { id: "intro-to-defi-tokens-liquidity-staking", title: "DeFi Concepts: Tokens, Liquidity Pools, and Staking", type: "video", duration: "20m", completed: false },
                        { id: "erc-standards-erc20-erc721-erc1155", title: "Implementing ERC Standards (ERC-20, ERC-721, ERC-1155)", type: "video", duration: "30m", completed: false },
                        { id: "lending-borrowing-and-modular-design", title: "Basic Lending/Borrowing Logic and Modular Design", type: "video", duration: "25m", completed: false },
                        { id: "events-logging-and-onchain-tracking", title: "Events, Logging, and On-Chain Data Tracking", type: "video", duration: "15m", completed: false }
                    ]
                },
                // Chapter 5
                {
                    title: "Module 5: Security & Best Practices",
                    lessons: [
                        { id: "common-vulnerabilities-reentrancy-overflow", title: "Common Vulnerabilities: Reentrancy and Overflow/Underflow", type: "video", duration: "25m", completed: false },
                        { id: "mitigation-strategies-and-secure-coding", title: "Mitigation Strategies and Secure Coding Patterns", type: "video", duration: "20m", completed: false },
                        { id: "input-validation-and-access-control", title: "Input Validation and Access Control (Ownable/Roles)", type: "video", duration: "18m", completed: false },
                        { id: "writing-secure-tests-in-foundry", title: "Writing Secure Tests and Fuzz Testing in Foundry", type: "video", duration: "30m", completed: false },
                        { id: "gas-optimization-techniques", title: "Gas Optimization for Smart Contracts", type: "video", duration: "15m", completed: false }
                    ]
                },
                // Chapter 6
                {
                    title: "Module 6: Deployment & Project Workflow",
                    lessons: [
                        { id: "contract-deployment-using-foundry", title: "Contract Deployment Scripts in Foundry", type: "video", duration: "20m", completed: false },
                        { id: "unit-testing-and-mock-contracts", title: "Advanced Unit Testing and Using Mocks", type: "video", duration: "25m", completed: false },
                        { id: "deploying-to-ethereum-testnets", title: "Deploying to Ethereum Testnets (Sepolia/Goerli)", type: "video", duration: "15m", completed: false },
                        { id: "transaction-lifecycle-and-gas-considerations", title: "Transaction Lifecycle and Mainnet Preparation", type: "video", duration: "18m", completed: false }
                    ]
                },
                // Chapter 7
                {
                    title: "Module 7: Proxy & Upgradeable Contracts",
                    lessons: [
                        { id: "intro-to-upgradeable-contracts-and-proxies", title: "Introduction to Upgradeable Contracts and Proxy Patterns", type: "video", duration: "20m", completed: false },
                        { id: "proxy-types-transparent-uups-beacon", title: "Proxy Types: Transparent, UUPS, and Beacon Proxies", type: "video", duration: "25m", completed: false },
                        { id: "storage-layout-and-initialization", title: "Storage Layout Collisions and Initializers", type: "video", duration: "22m", completed: false },
                        { id: "testing-and-simulating-upgrades", title: "Security Considerations and Simulating Upgrades in Foundry", type: "video", duration: "30m", completed: false }
                    ]
                }
            ]
        },

    // Course: SMART CONTRACT SECURITY
    "smart-contract-security-audit": {
        id: "smart-contract-security-audit",
        tags: [
            { label: "Specialization Track", icon: "shield" },
            { label: "Secure Solidity", icon: "code" },
            { label: "Auditing", icon: "bug" },
          ],
        title: "Smart Contract Security & Auditing",
        track: "Blockchain & Smart Contract Security",
        level: "Advanced to Expert",
        duration: "8 Weeks",
        description: "Smart Contract Security & Auditing gives you a clear and practical introduction to how modern smart contract risks work. You’ll learn the basics of access control issues, reentrancy, oracles, fuzzing, MEV threats, DoS vectors, and reporting patterns used in audits risk notes. The course builds your understanding step-by-step so you can see how each layer works together to keep systems and data safe, preparing you for more advanced security learning.",
        
        learningObjectives: [
            "Understand core security principles that protect blockchain applications",
            "Identify common vulnerabilities such as reentrancy, access flaws, and oracle risks",
            "Analyze real smart contract failures to understand root causes",
            "Use tools like Foundry and Slither to test, fuzz, and detect issues",
            "Write clear and structured reports outlining impact and mitigation",
            "Build confidence to move into auditing, bug bounty, or security research roles"
        ],
       
        prerequisites: [
            "Basic knowledge of Solidity or smart contract development",
            "Comfort reading simple code and interacting with blockchain tools",
            "No prior auditing or security experience required",
            "A laptop capable of running testing frameworks and smart contract tools"
        ],

        modules: [

            // Chapter 1
            {
                title: "Module 1: Introduction to Smart Contract Security",
                lessons: [
                    { id: "overview-blockchain-security-principles", title: "Overview of Blockchain Security Principles", type: "video", duration: "15m", completed: false },
                    { id: "security-considerations-solidity-ethereum", title: "Security Considerations for Solidity & Ethereum", type: "video", duration: "20m", completed: false },
                    { id: "common-attack-surfaces-smart-contracts", title: "Common Attack Surfaces in Smart Contracts", type: "video", duration: "18m", completed: false },
                    { id: "lifecycle-secure-smart-contract-development", title: "Lifecycle of Secure Smart Contract Development", type: "video", duration: "15m", completed: false },
                    { id: "tools-frameworks-testing-auditing", title: "Tools & Frameworks for Testing and Auditing (Foundry/Slither)", type: "video", duration: "20m", completed: false }
                ]
            },
            // Chapter 2
            {
                title: "Module 2: Access Control & Authorization Vulnerabilities",
                lessons: [
                    { id: "concept-access-control-permissioning", title: "Concept: Understanding Access Control & Permissioning", type: "video", duration: "15m", completed: false },
                    { id: "root-cause-missing-misconfigured-access", title: "Root Cause: Missing or Misconfigured Access Control", type: "video", duration: "18m", completed: false },
                    { id: "exploitation-unauthorized-privilege-escalation", title: "Exploitation: Unauthorized Calls & Privilege Escalation", type: "video", duration: "20m", completed: false },
                    { id: "mitigation-rbac-ownership-patterns", title: "Mitigation: RBAC, Ownership Patterns, and Modifiers", type: "video", duration: "22m", completed: false },
                    { id: "reporting-improper-access-security-impact", title: "Reporting: Documenting Improper Access & Impact", type: "video", duration: "12m", completed: false }
                ]
            },
            // Chapter 3
            {
                title: "Module 3: Reentrancy Vulnerabilities",
                lessons: [
                    { id: "concept-external-calls-control-flow", title: "Concept: External Calls & Unexpected Control Flow", type: "video", duration: "15m", completed: false },
                    { id: "root-cause-checks-effects-interactions", title: "Root Cause: Failure of Checks-Effects-Interactions Pattern", type: "video", duration: "20m", completed: false },
                    { id: "exploitation-recursive-calls-fund-draining", title: "Exploitation: Recursive Calls & Draining Funds", type: "video", duration: "25m", completed: false },
                    { id: "mitigation-reentrancy-guards-state-updates", title: "Mitigation: Reentrancy Guards & Proper State Updates", type: "video", duration: "18m", completed: false },
                    { id: "reporting-attack-vector-impact-analysis", title: "Reporting: Describing Attack Vectors & Impact", type: "video", duration: "15m", completed: false }
                ]
            },
            // Chapter 4
            {
                title: "Module 4: Oracle Manipulation",
                lessons: [
                    { id: "concept-oracles-external-data", title: "Concept: Using Oracles for Contract Logic", type: "video", duration: "15m", completed: false },
                    { id: "root-cause-reliance-untrusted-oracles", title: "Root Cause: Reliance on Untrusted/Manipulable Oracles", type: "video", duration: "18m", completed: false },
                    { id: "exploitation-flash-loans-price-manipulation", title: "Exploitation: Flash Loans & Price Manipulation Attacks", type: "video", duration: "25m", completed: false },
                    { id: "mitigation-decentralized-oracles-timelocks", title: "Mitigation: Decentralized Oracles (Chainlink), TWAP, Timelocks", type: "video", duration: "22m", completed: false },
                    { id: "reporting-affected-contracts-severity", title: "Reporting: Identifying Affected Contracts & Severity", type: "video", duration: "12m", completed: false }
                ]
            },
            // Chapter 5
            {
                title: "Module 5: Fuzzing & Input Validation",
                lessons: [
                    { id: "concept-handling-unexpected-inputs", title: "Concept: Handling Unexpected or Malformed Inputs", type: "video", duration: "15m", completed: false },
                    { id: "root-cause-improper-validation-unchecked-data", title: "Root Cause: Improper Validation & Unchecked User Data", type: "video", duration: "18m", completed: false },
                    { id: "exploitation-unhandled-errors-state-corruption", title: "Exploitation: Triggering Errors & State Corruption", type: "video", duration: "20m", completed: false },
                    { id: "mitigation-sanitization-fuzzing", title: "Mitigation: Input Sanitization, Preconditions & Fuzzing", type: "video", duration: "25m", completed: false },
                    { id: "reporting-fuzzing-test-cases-fixes", title: "Reporting: Documenting Fuzzing Cases & Fixes", type: "video", duration: "15m", completed: false }
                ]
            },
            // Chapter 6
            {
                title: "Module 6: Miner Extractable Value (MEV)",
                lessons: [
                    { id: "concept-transaction-ordering-manipulation", title: "Concept: Transaction Ordering Manipulation", type: "video", duration: "18m", completed: false },
                    { id: "root-cause-predictable-state-changes", title: "Root Cause: Predictable State & Sequence Dependencies", type: "video", duration: "15m", completed: false },
                    { id: "exploitation-front-running-sandwich-attacks", title: "Exploitation: Front-running, Back-running, Sandwich Attacks", type: "video", duration: "25m", completed: false },
                    { id: "mitigation-private-mempools-fair-ordering", title: "Mitigation: Private Mempools & Fair Ordering Protocols", type: "video", duration: "20m", completed: false },
                    { id: "reporting-mev-scenarios-risk", title: "Reporting: MEV Exploitation Scenarios & Risk", type: "video", duration: "15m", completed: false }
                ]
            },
            // Chapter 7
            {
                title: "Module 7: Denial-of-Service (DoS) Vulnerabilities",
                lessons: [
                    { id: "concept-blocking-critical-operations", title: "Concept: Blocking Critical Contract Operations", type: "video", duration: "15m", completed: false },
                    { id: "root-cause-gas-exhaustion-unbounded-loops", title: "Root Cause: Gas Exhaustion & Unbounded Loops", type: "video", duration: "18m", completed: false },
                    { id: "exploitation-halted-execution", title: "Exploitation: Forcing Function Failures & Halts", type: "video", duration: "20m", completed: false },
                    { id: "mitigation-circuit-breakers-gas-efficiency", title: "Mitigation: Circuit Breakers & Gas-Efficient Loops", type: "video", duration: "22m", completed: false },
                    { id: "reporting-dos-scenarios-recommended-fixes", title: "Reporting: DoS Scenarios & Recommended Fixes", type: "video", duration: "15m", completed: false }
                ]
            }
        ]
    },
/////////////////////////////////////////////////----Track Syllabu END ---/////////////////////////////////////////////////////////////////////////////////////////////////////////////
  
// Course: Bug Bounty Career 
"bug-bounty-career": {
    id: "bug-bounty-career",
    tags: [
        { label: "Final Track", icon: "shield" },
        { label: "Certification", icon: "certificate" },
        { label: "Career", icon: "briefcase" },
      ],
    title: "Bug Bounty & Career Launchpad",
    track: "Professional Launch",
    level: "Intermediate",
    duration: "5 Weeks",
    description: "Bug Bounty Career gives you a clear and practical introduction to how modern VAPT workflows operate. You’ll learn the basics of VAPT phases, bug bounty structures,Web2 and Web3 security, reporting practices, tools, certifications and career pathways. industry standards guide. The course builds your understanding step-by-step so you can see how each layer works together to keep systems and data safe, preparing you for more advanced security learning.",
    modules: [
        // Chapter 1
        { 
            title: "Module 1: Fundamentals of VAPT", 
            lessons: [
                { id: "introduction-to-vapt-vulnerability-assessment-&-penetration-testing", title: "Introduction to VAPT (Vulnerability Assessment & Penetration Testing)", type: "video", duration: "12m 30s", completed: false },
                { id: "vulnerability-scanning-vs-penetration-testing", title: "Vulnerability Scanning vs Penetration Testing", type: "video", duration: "10m 15s", completed: false },
                { id: "scoping-planning-and-legal/ethical-considerations", title: "Scoping, Planning, and Legal/Ethical Considerations", type: "video", duration: "18m 00s", completed: false },
                { id: "manual-vs-automated-testing", title: "Manual vs Automated Testing", type: "video", duration: "8m 40s", completed: false },
                { id: "lifecycle-of-a-vapt-engagement-reconnaissance-exploitation-reporting", title: "Lifecycle of a VAPT Engagement: Reconnaissance, Exploitation, Reporting", type: "video", duration: "25m 00s", completed: false }
            ] 
        },
        // Chapter 2
        { 
            title: "Module 2: Bug Bounty Programs", 
            lessons: [
                { id: "overview-of-bug-bounty-programs-and-their-importance", title: "Overview of Bug Bounty Programs and their Importance", type: "video", duration: "14m 20s", completed: false },
                { id: "types-of-programs-public-private-invite-only-contests", title: "Types of Programs: Public, Private, Invite-Only, Contests", type: "video", duration: "16m 50s", completed: false },
                { id: "responsible-disclosure-program-rdp-vs-vdp", title: "Responsible Disclosure Program (RDP) vs VDP", type: "video", duration: "9m 30s", completed: false },
                { id: "popular-platforms-hackerone-bugcrowd-synack-immunefi", title: "Popular Platforms: HackerOne, Bugcrowd, Synack, Immunefi", type: "video", duration: "15m 00s", completed: false },
                { id: "understanding-program-scope-rules-and-guidelines", title: "Understanding Program Scope, Rules, and Guidelines", type: "video", duration: "17m 45s", completed: false },
                { id: "contests-and-competitions-ctf-formats-scoring-leaderboards", title: "Contests and Competitions: CTF Formats, Scoring, Leaderboards", type: "video", duration: "11m 10s", completed: false }
            ]
        },
        // Chapter 3
        { 
            title: "Module 3: Web 2.0 and Web 3.0 Security Overview", 
            lessons: [
                { id: "key-differences-between-web-2.0-and-web-3.0-ecosystems", title: "Key Differences between Web 2.0 and Web 3.0 Ecosystems", type: "video", duration: "15m 30s", completed: false },
                { id: "web-2.0-centralized-servers-apis-platform-controlled-data", title: "Web 2.0: Centralized Servers, APIs, Platform-Controlled Data", type: "video", duration: "10m 40s", completed: false },
                { id: "web-3.0-decentralized-nodes-smart-contracts-user-controlled-data", title: "Web 3.0: Decentralized Nodes, Smart Contracts, User-Controlled Data", type: "video", duration: "18m 15s", completed: false },
                { id: "security-responsibilities-in-web-2.0-vs-web-3.0", title: "Security Responsibilities in Web 2.0 vs Web 3.0", type: "video", duration: "14m 55s", completed: false },
                { id: "vulnerability-reporting-considerations-for-both-ecosystems", title: "Vulnerability Reporting Considerations for Both Ecosystems", type: "video", duration: "11m 00s", completed: false },
                { id: "career-roadmap-starting-with-web-2.0-security", title: "Career Roadmap: Starting with Web 2.0 Security", type: "video", duration: "8m 20s", completed: false },
                { id: "career-roadmap-starting-with-web-3.0-security", title: "Career Roadmap: Starting with Web 3.0 Security", type: "video", duration: "10m 00s", completed: false }
            ]
        },
        // Chapter 4
        { 
            title: "Module 4: Reporting, Tools & Professional Practices", 
            lessons: [
                { id: "writing-professional-vulnerability-reports", title: "Writing Professional Vulnerability Reports", type: "video", duration: "20m 00s", completed: false },
                { id: "cvss-scoring-and-impact-prioritization", title: "CVSS Scoring and Impact Prioritization", type: "video", duration: "15m 30s", completed: false },
                { id: "professional-vs-unprofessional-reporting-standards", title: "Professional vs Unprofessional Reporting Standards", type: "video", duration: "10m 45s", completed: false },
                { id: "coordinating-with-platforms-and-clients-for-disclosure", title: "Coordinating with Platforms and Clients for Disclosure", type: "video", duration: "13m 15s", completed: false },
                { id: "essential-tools-for-scanning-enumeration-and-automated-testing", title: "Essential Tools for Scanning, Enumeration, and Automated Testing", type: "video", duration: "25m 00s", completed: false },
                { id: "continuous-skill-enhancement-and-learning-best-practices", title: "Continuous Skill Enhancement and Learning Best Practices", type: "video", duration: "11m 20s", completed: false }
            ]
        },
        // Chapter 5
        { 
            title: "Module 5: Career Opportunities, Growth & Placement", 
            lessons: [
                { id: "career-paths-bug-bounty-hunter-vapt-consultant-web3-security-auditor", title: "Career Paths: Bug Bounty Hunter, VAPT Consultant, Web3 Security Auditor", type: "video", duration: "16m 40s", completed: false },
                { id: "building-a-professional-portfolio-and-reputation", title: "Building a Professional Portfolio and Reputation", type: "video", duration: "14m 10s", completed: false },
                { id: "certifications-oscp-ejpt-ceh-auditing-certifications", title: "Certifications: OSCP, eJPT, CEH, Auditing Certifications", type: "video", duration: "18m 00s", completed: false },
                { id: "participating-in-contests-ctfs-and-hackathons", title: "Participating in Contests, CTFs, and Hackathons", type: "video", duration: "11m 50s", completed: false },
                { id: "networking-and-community-engagement-for-career-advancement", title: "Networking and Community Engagement for Career Advancement", type: "video", duration: "10m 30s", completed: false },
                { id: "ethical-and-legal-responsibilities-in-security-testing", title: "Ethical and Legal Responsibilities in Security Testing", type: "video", duration: "15m 00s", completed: false },
                { id: "placement-strategy-prepare-portfolio-and-ctf-achievements", title: "Placement Strategy: Prepare Portfolio and CTF Achievements", type: "video", duration: "12m 20s", completed: false },
                { id: "placement-strategy-build-linkedin/github-presence", title: "Placement Strategy: Build LinkedIn/GitHub Presence", type: "video", duration: "8m 50s", completed: false },
                { id: "placement-strategy-interview-preparation-with-practical-scenarios", title: "Placement Strategy: Interview Preparation with Practical Scenarios", type: "video", duration: "15m 45s", completed: false }
            ]
        },
    ]
    }
  };