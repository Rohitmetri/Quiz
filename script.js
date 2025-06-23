// Quiz Questions Data
const questions = [
    {
        question: "User A is writing a sensitive email message to user B outside the local network. User A has chosen to use PKI to secure his message and ensure only user B can read the sensitive email. At what layer of the OSI layer does the encryption and decryption of the message take place?",
        options: [
            "Application",
            "Transport",
            "Session",
            "Presentation"
        ],
        correctAnswer: 3
    },
    {
        question: "A new wireless client is configured to join a 802.11 network. This client uses the same hardware and software as many of the other clients on the network. The client can see the network, but cannot connect. A wireless packet sniffer shows that the Wireless Access Point (WAP) is not responding to the association requests being sent by the wireless client. What is a possible source of this problem?",
        options: [
            "The WAP does not recognize the client's MAC address",
            "The client cannot see the SSID of the wireless network",
            "Client is configured for the wrong channel",
            "The wireless client is not configured to use DHCP"
        ],
        correctAnswer: 0
    },
    // All other questions from your list...
    {
        question: "Which of the following incident handling process phases is responsible for defining rules, collaborating human workforce, creating a back-up plan, and testing the plans for an organization?",
        options: [
            "Preparation phase",
            "Containment phase",
            "Identification phase",
            "Recovery phase"
        ],
        correctAnswer: 0
    },
    {
    question: "If a tester is attempting to ping a target that exists but receives no response or a response that states the destination is unreachable, ICMP may be disabled and the network may be using TCP. Which other option could the tester use to get a response from a host using TCP?",
    options: [
      "Traceroute",
      "Hping",
      "TCP ping",
      "Broadcast ping"
    ],
    correctAnswer: 2 // TCP ping
  },
  {
    question: "Which is the first step followed by Vulnerability Scanners for scanning a network?",
    options: [
      "OS Detection",
      "Firewall detection",
      "TCP/UDP Port scanning",
      "Checking if the remote host is alive"
    ],
    correctAnswer: 3 // Checking if the remote host is alive
  },
  {
    question: "Which of the following programs is usually targeted at Microsoft Office products?",
    options: [
      "Polymorphic virus",
      "Multipart virus",
      "Macro virus",
      "Stealth virus"
    ],
    correctAnswer: 2 // Macro virus
  },
  {
    question: "A technician is resolving an issue where a computer is unable to connect to the Internet using a wireless access point. The computer is able to transfer files locally to other machines, but cannot successfully reach the Internet. When the technician examines the IP address and default gateway, they are both on the 192.168.1.0/24 network. Which of the following has occurred?",
    options: [
      "The computer is not using a private IP address.",
      "The gateway is not routing to a public IP address.",
      "The gateway and the computer are not on the same network.",
      "The computer is using an invalid IP address."
    ],
    correctAnswer: 1 // The gateway is not routing to a public IP address
  },
  {
    question: "Identify the UDP port that Network Time Protocol (NTP) uses as its primary means of communication?",
    options: [
      "113",
      "69",
      "123",
      "161"
    ],
    correctAnswer: 2 // 123
  },
  {
    question: "Which of the following tools performs comprehensive tests against web servers, including dangerous files and CGIs?",
    options: [
      "Nikto",
      "John the Ripper",
      "Dsniff",
      "Snort"
    ],
    correctAnswer: 0 // Nikto
  },
  {
    question: "An incident investigator asks to receive a copy of the event logs from all firewalls, proxy servers, and Intrusion Detection Systems (IDS) on the network of an organization that has experienced a possible breach of security. When the investigator attempts to correlate the information in all of the logs, the sequence of many of the logged events does not match up. What is the most likely cause?",
    options: [
      "The network devices are not all synchronized.",
      "Proper chain of custody was not observed while collecting the logs.",
      "The attacker altered or erased events from the logs.",
      "The security breach was a false positive."
    ],
    correctAnswer: 0 // The network devices are not all synchronized
  },
   {
    question: "During a black-box pen test you attempt to pass IRC traffic over port 80/TCP from a compromised web enabled host. The traffic gets blocked; however, outbound HTTP traffic is unimpeded. What type of firewall is inspecting outbound traffic?",
    options: [
      "Circuit",
      "Stateful",
      "Application",
      "Packet Filtering"
    ],
    correctAnswer: 2 // Application
  },
  {
    question: "By using a smart card and pin, you are using a two-factor authentication that satisfies",
    options: [
      "Something you are and something you remember",
      "Something you have and something you know",
      "Something you know and something you are",
      "Something you have and something you are"
    ],
    correctAnswer: 1 // Something you have and something you know
  },
  {
    question: "Fill in the blank: '______ is an attack type for a rogue Wi-Fi access point that appears to be legitimate...'",
    options: [
      "Evil Twin Attack",
      "Sinkhole Attack",
      "Collision Attack",
      "Signal Jamming Attack"
    ],
    correctAnswer: 0 // Evil Twin Attack
  },
  {
    question: "What term describes the amount of risk that remains after the vulnerabilities are classified and the countermeasures have been deployed?",
    options: [
      "Residual risk",
      "Impact risk",
      "Deferred risk",
      "Inherent risk"
    ],
    correctAnswer: 0 // Residual risk
  },
  {
    question: "Which tool can be used to perform session splicing attacks?",
    options: [
      "tcpsplice",
      "Burp",
      "Hydra",
      "Whisker"
    ],
    correctAnswer: 3 // Whisker
  },
  {
    question: "What is the best Nmap command to enumerate all machines in the 10.10.0.0/24 network quickly?",
    options: [
      "nmap -T4 -q 10.10.0.0/24",
      "nmap -T4 -F 10.10.0.0/24",
      "nmap -T4 -r 10.10.1.0/24",
      "nmap -T4 -O 10.10.0.0/24"
    ],
    correctAnswer: 1 // nmap -T4 -F 10.10.0.0/24
  },
  {
    question: "Which is the BEST way to defend against network sniffing?",
    options: [
      "Using encryption protocols to secure network communications",
      "Register all machines MAC Address in a Centralized Database",
      "Use Static IP Address",
      "Restrict Physical Access to Server Rooms hosting Critical Servers"
    ],
    correctAnswer: 0 // Using encryption protocols...
  },
  {
    question: "Although FTP traffic is not encrypted by default, which layer 3 protocol would allow for end-to-end encryption of the connection?",
    options: [
      "SFTP",
      "Ipsec",
      "SSL",
      "FTPS"
    ],
    correctAnswer: 1 // Ipsec
  },
  {
    question: "What may be the problem when websites are accessible by IP but not by URL?",
    options: [
      "Traffic is Blocked on UDP Port 53",
      "Traffic is Blocked on TCP Port 80",
      "Traffic is Blocked on TCP Port 54",
      "Traffic is Blocked on UDP Port 80"
    ],
    correctAnswer: 0 // Traffic is Blocked on UDP Port 53
  },
  {
    question: "Which tool is used to detect wireless LANs using 802.11a/b/g/n WLAN standards on a linux platform?",
    options: [
      "Kismet",
      "Abel",
      "Netstumbler",
      "Nessus"
    ],
    correctAnswer: 0 // Kismet
  },
  {
    question: "What is the name of the attack where an attacker creates a transparent 'iframe' in front of a clickable URL?",
    options: [
      "Session Fixation",
      "HTML Injection",
      "HTTP Parameter Pollution",
      "Clickjacking Attack"
    ],
    correctAnswer: 3 // Clickjacking Attack
  },
  {
    question: "What kind of vulnerability must be present to make the described FTP server attack possible?",
    options: [
      "File system permissions",
      "Privilege escalation",
      "Directory traversal",
      "Brute force login"
    ],
    correctAnswer: 0 // File system permissions
  },
  {
    question: "Which method of password cracking takes the most time and effort?",
    options: [
      "Dictionary attack",
      "Shoulder surfing",
      "Rainbow tables",
      "Brute force"
    ],
    correctAnswer: 3 // Brute force
  },
  {
    question: "What does the -oX flag do in an Nmap scan?",
    options: [
      "Perform an eXpress scan",
      "Output the results in truncated format to the screen",
      "Output the results in XML format to a file",
      "Perform an Xmas scan"
    ],
    correctAnswer: 2 // Output the results in XML format to a file
  },
  {
    question: "What is the first step a bank should take before enabling audit features?",
    options: [
      "Perform a vulnerability scan of the system",
      "Determine the impact of enabling the audit feature",
      "Perform a cost/benefit analysis of the audit feature",
      "Allocate funds for staffing of audit log review"
    ],
    correctAnswer: 1 // Determine the impact...
  },
  {
    question: "Which IDS is best for large environments where critical assets need extra scrutiny?",
    options: [
      "Honeypots",
      "Firewalls",
      "Network-based intrusion detection system (NIDS)",
      "Host-based intrusion detection system (HIDS)"
    ],
    correctAnswer: 2 // NIDS
  },
  {
    question: "The collection of potentially actionable, overt, and publicly available information is known as",
    options: [
      "Open-source intelligence",
      "Real intelligence",
      "Social intelligence",
      "Human intelligence"
    ],
    correctAnswer: 0 // Open-source intelligence
  },
  {
    question: "What is one advantage of using both symmetric and asymmetric cryptography in SSL/TLS?",
    options: [
      "Supporting both types allows less-powerful devices to use symmetric encryption",
      "Symmetric algorithms provide a failsafe when asymmetric methods fail",
      "Symmetric encryption allows secure out-of-band session key transmission",
      "Asymmetric cryptography is computationally expensive but good for key negotiation"
    ],
    correctAnswer: 3 // Asymmetric cryptography is...
  },
  {
    question: "What is the approximate annual cost of the described hard drive failure scenario?",
    options: [
      "$1320",
      "$440",
      "$100",
      "$146"
    ],
    correctAnswer: 1 // $440
  },
  {
    question: "What is the known plaintext attack used against DES with two keys?",
    options: [
      "Man-in-the-middle attack",
      "Meet-in-the-middle attack",
      "Replay attack",
      "Traffic analysis attack"
    ],
    correctAnswer: 1 // Meet-in-the-middle attack
  },
  {
    question: "What can be said about Steve's two-phase identification system?",
    options: [
      "It implements just one authentication factor",
      "It implements two factors: physical object and characteristic",
      "It will have a high level of false positives",
      "Biological motion cannot be used to identify people"
    ],
    correctAnswer: 1 // Two factors...
  },
  {
    question: "What is not a PCI compliance recommendation?",
    options: [
      "Use a firewall between public network and payment card data",
      "Use encryption for all transmission of card holder data",
      "Rotate credit card handling employees yearly",
      "Limit access to card holder data"
    ],
    correctAnswer: 2 // Rotate employees...
  },
  {
    question: "What is the minimum number of network connections in a multihomed firewall?",
    options: [
      "3",
      "5",
      "4",
      "2"
    ],
    correctAnswer: 0 // 3
  },
  {
    question: "Which risk decision is best when risk decreased from 50% to 10% with 20% threshold?",
    options: [
      "Accept the risk",
      "Introduce more controls to bring risk to 0%",
      "Mitigate the risk",
      "Avoid the risk"
    ],
    correctAnswer: 0 // Accept the risk
  },
  {
    question: "What is the recommended architecture for deploying a new web-based software package requiring three separate servers?",
    options: [
      "All three servers need to be placed internally",
      "A web server facing the Internet, an application server on the internal network, a database server on the internal network",
      "A web server and the database server facing the Internet, an application server on the internal network",
      "All three servers need to face the Internet so that they can communicate between themselves"
    ],
    correctAnswer: 1 // Web server external, app/db servers internal
  },
  {
    question: "Which tool was probably used to inject HTML code in a MITM attack using a rogue wireless AP?",
    options: [
      "Wireshark",
      "Ettercap",
      "Aircrack-ng",
      "Tcpdump"
    ],
    correctAnswer: 1 // Ettercap
  },
  {
    question: "Which IPSec mode should be used to assure security and confidentiality of data within the same LAN?",
    options: [
      "ESP transport mode",
      "ESP confidential",
      "AH permiscuous",
      "AH Tunnel mode"
    ],
    correctAnswer: 0 // ESP transport mode
  },
  {
    question: "What is the term for the research time hackers spend gathering information about a company for phishing?",
    options: [
      "Exploration",
      "Investigation",
      "Reconnaissance",
      "Enumeration"
    ],
    correctAnswer: 2 // Reconnaissance
  },
  {
    question: "Which virus hides from anti-virus programs by altering service call interruptions?",
    options: [
      "Macro virus",
      "Stealth/Tunneling virus",
      "Cavity virus",
      "Polymorphic virus"
    ],
    correctAnswer: 1 // Stealth/Tunneling virus
  },
  {
    question: "What restriction does 'Gray-box testing' methodology enforce?",
    options: [
      "Only the external operation is accessible",
      "The internal operation is only partly accessible",
      "Only the internal operation is known",
      "The internal operation is completely known"
    ],
    correctAnswer: 1 // Internal operation partly accessible
  },
  {
    question: "What type of alert is generated when legitimate admin activity triggers an IDS?",
    options: [
      "False negative",
      "True negative",
      "True positive",
      "False positive"
    ],
    correctAnswer: 3 // False positive
  },
  {
    question: "What tool should be used to perform a Blackjacking attack?",
    options: [
      "Paros Proxy",
      "BBProxy",
      "Blooover",
      "BBCrack"
    ],
    correctAnswer: 1 // BBProxy
  },
  {
    question: "Which Nmap script detects available HTTP methods?",
    options: [
      "http-methods",
      "http enum",
      "http-headers",
      "http-git"
    ],
    correctAnswer: 0 // http-methods
  },
  {
    question: "What best describes a counter-based authentication system?",
    options: [
      "Biometric system using behavioral attributes",
      "Biometric system using physical attributes",
      "Creates one-time passwords encrypted with secret keys",
      "Uses passphrases converted into virtual passwords"
    ],
    correctAnswer: 2 // One-time passwords
  },
  {
    question: "Which is a low-tech way of gaining unauthorized access to systems?",
    options: [
      "Social Engineering",
      "Eavesdropping",
      "Scanning",
      "Sniffing"
    ],
    correctAnswer: 0 // Social Engineering
  },
  {
    question: "Which system contains domain name registration contact information?",
    options: [
      "WHOIS",
      "CAPTCHA",
      "IANA",
      "IETF"
    ],
    correctAnswer: 0 // WHOIS
  },
  {
    question: "Why is a penetration test more thorough than a vulnerability scan?",
    options: [
      "Vulnerability scans only do host discovery and port scanning",
      "Penetration tests actively exploit vulnerabilities",
      "Penetration tests are automated while scans require engagement",
      "Penetration test tools have more comprehensive databases"
    ],
    correctAnswer: 1 // Actively exploits vulnerabilities
  },
  {
    question: "What is true about the text message from 'Yahoo Bank'?",
    options: [
      "This is a scam as @yahoo addresses aren't used by customer service",
      "This is a scam because Bob doesn't know Scott",
      "Bob should write to verify Scott's identity",
      "This is probably legitimate"
    ],
    correctAnswer: 0 // Scam due to @yahoo address
  },
  {
    question: "What is the Shellshock bash vulnerability attempting to do?",
    options: [
      "Remove the passwd file",
      "Change all passwords in passwd",
      "Add new user to passwd",
      "Display passwd content"
    ],
    correctAnswer: 3 // Display passwd content
  },
  {
    question: "Which is assured by the use of a hash?",
    options: [
      "Authentication",
      "Confidentiality",
      "Availability",
      "Integrity"
    ],
    correctAnswer: 3 // Integrity
  },
  {
    question: "What results will 'site:target.com -site:Marketing.target.com accounting' return?",
    options: [
      "Results from marketing.target.com in target.com excluding 'accounting'",
      "Results matching all words",
      "Results for target.com and Marketing.target.com including 'accounting'",
      "Results for 'accounting' in target.com but not Marketing.target.com"
    ],
    correctAnswer: 3 // Accounting in target.com excluding Marketing subdomain
  },
  {
    question: "What is the SMTP command to transmit email over TLS?",
    options: [
      "OPPORTUNISTICTLS",
      "UPGRADETLS",
      "FORCETLS",
      "STARTTLS"
    ],
    correctAnswer: 3 // STARTTLS
  },
  {
    question: "What is a 'rubber-hose' attack in cryptanalysis?",
    options: [
      "Forcing keystream through hardware-accelerated devices",
      "Backdoor in cryptographic algorithm",
      "Extraction of secrets through coercion or torture",
      "Decrypting by logical assumptions about plaintext"
    ],
    correctAnswer: 2 // Coercion or torture
  },
  {
    question: "What Wireshark filter shows connections from snort (192.168.0.99) to kiwi syslog (192.168.0.150)?",
    options: [
      "tcp.srcport == 514 && ip.src == 192.168.0.99",
      "tcp.srcport == 514 && ip.src == 192.168.150",
      "tcp.dstport == 514 && ip.dst == 192.168.0.99",
      "tcp.dstport == 514 && ip.dst == 192.168.0.150"
    ],
    correctAnswer: 3 // Destination port 514 to kiwi syslog IP
  },
  {
    question: "What two conditions must a digital signature meet?",
    options: [
      "Same length as physical signature and unique",
      "Unforgeable and authentic",
      "Unique with special characters",
      "Legible and neat"
    ],
    correctAnswer: 1 // Unforgeable and authentic
  },
  {
    question: "What security breach does deleting HTTP cookies mitigate?",
    options: [
      "Access to SQL database credentials",
      "Access to sites trusting the browser by stealing auth credentials",
      "Access to passwords stored on user's computer",
      "Determining browser usage patterns"
    ],
    correctAnswer: 1 // Stealing authentication credentials
  },
  {
    question: "What is correct about digital signatures?",
    options: [
      "Cannot be moved as it's document hash encrypted with private key",
      "May be used in different documents of same type",
      "Cannot be moved as it's plain hash of content",
      "Issued once per user and usable everywhere"
    ],
    correctAnswer: 0 // Hash encrypted with private key
  },
  {
    question: "What follows a successful STP manipulation attack?",
    options: [
      "Create SPAN entry on spoofed root bridge to redirect traffic",
      "Activate OSPF on spoofed root bridge",
      "Repeat to escalate to DoS",
      "Repeat against all L2 switches"
    ],
    correctAnswer: 0 // Create SPAN entry
  },
  {
    question: "Which Linux-based tool can change Windows user passwords?",
    options: [
      "John the Ripper",
      "SET",
      "CHNTPW",
      "Cain & Abel"
    ],
    correctAnswer: 2 // CHNTPW
  },
  {
    question: "What does a firewall check to block specific ports/applications?",
    options: [
      "Transport layer port numbers and application layer headers",
      "Presentation layer headers and session layer port numbers",
      "Network layer headers and session layer port numbers",
      "Application layer port numbers and transport layer headers"
    ],
    correctAnswer: 0 // Transport ports and app headers
  },
  {
    question: "Which file does an attacker modify to redirect 'www.MyPersonalBank.com'?",
    options: [
      "Boot.ini",
      "Sudoers",
      "Networks",
      "Hosts"
    ],
    correctAnswer: 3 // Hosts file
  },
  {
    question: "What provides origin authentication of DNS data to prevent poisoning?",
    options: [
      "DNSSEC",
      "Resource records",
      "Resource transfer",
      "Zone transfer"
    ],
    correctAnswer: 0 // DNSSEC
  },
  {
    question: "Which incident handling phase defines rules and creates backup plans?",
    options: [
      "Preparation phase",
      "Containment phase",
      "Identification phase",
      "Recovery phase"
    ],
    correctAnswer: 0 // Preparation phase
  },
  {
    question: "What mode passes all traffic to CPU rather than only intended frames?",
    options: [
      "Multi-cast mode",
      "Promiscuous mode",
      "WEM",
      "Port forwarding"
    ],
    correctAnswer: 1 // Promiscuous mode
  },
  {
    question: "What is the best security policy for network elements in a secured data center?",
    options: [
      "Harden with user IDs/strong passwords, perform regular tests/audits",
      "No additional measures needed if physical access restricted",
      "No specific measures needed with firewalls/IPS",
      "Accept attacks as inevitable, maintain backup site"
    ],
    correctAnswer: 0 // Harden elements and perform audits
  },
  {
    question: "What type of cryptography are PGP, SSL, and IKE examples of?",
    options: [
      "Digest",
      "Secret Key",
      "Public Key",
      "Hash Algorithm"
    ],
    correctAnswer: 2 // Public Key
  },
  {
    question: "What hacking process is Peter doing when researching DX Company online?",
    options: [
      "Scanning",
      "Footprinting",
      "Enumeration",
      "System Hacking"
    ],
    correctAnswer: 1 // Footprinting
  },
  {
  question: "Mr. Omkar conducted a tool-based vulnerability assessment and detected two vulnerabilities. However, upon further analysis, he realized that these were not actual vulnerabilities. What would these issues be classified as?",
  options: [
    "False positives",
    "True negatives",
    "True positives",
    "False negatives"
  ],
  correctAnswer: 0 // False positives
},

{
  question: "An attacker scans vulnerable machines to create a list of targets. After infecting the machines, the list is divided, with half assigned to newly compromised machines. The scanning continues simultaneously, allowing the malware to spread quickly. What is this technique called?",
  options: [
    "Subnet scanning technique",
    "Hit-list scanning technique",
    "Permutation scanning technique",
    "Topological scanning technique"
  ],
  correctAnswer: 1 // Hit-list scanning technique
},

{
  question: "What type of attack involves injecting 'Carriage Return' and 'Line Feed' characters to manipulate HTTP headers?",
  options: [
    "Server-Side JS Injection",
    "Log Injection",
    "CRLF Injection",
    "HTML Injection"
  ],
  correctAnswer: 2 // CRLF Injection
},

{
  question: "Which wireless standard has a bandwidth of up to 54 Mbps and operates in the regulated 5 GHz spectrum?",
  options: [
    "802.11i",
    "802.11n",
    "802.11a",
    "802.11g"
  ],
  correctAnswer: 2 // 802.11a
},

{
  question: "Which Nmap flag enables a stealth scan to reduce IDS detection?",
  options: [
    "-sT",
    "-sS",
    "-sM",
    "-sU"
  ],
  correctAnswer: 1 // -sS
},

{
  question: "Taylor, a security professional, uses a tool to monitor her company's website, analyze website traffic, and track the geographical location of visitors. Which tool is used in this scenario?",
  options: [
    "Webroot",
    "Web-Stat",
    "WebSite-Watcher",
    "WAFW00F"
  ],
  correctAnswer: 1 // Web-Stat
},

{
  question: "A DDoS attack targets layer 7 by sending partial HTTP requests to a web server. The server keeps multiple connections open, waiting for the requests to complete, leading to resource exhaustion. Which attack is being described?",
  options: [
    "Session splicing",
    "Desynchronization",
    "Phlashing",
    "Slowloris attack"
  ],
  correctAnswer: 3 // Slowloris attack
},

{
  question: "Gilbert, a Web Developer, uses a centralized web API to simplify data management and ensure integrity. The API utilizes HTTP methods like PUT, POST, GET, and DELETE, improving performance, scalability, reliability, and portability. What type of web-service API is being used?",
  options: [
    "SOAP API",
    "JSON-RPC",
    "RESTful API",
    "REST API"
  ],
  correctAnswer: 2 // RESTful API
},

{
  question: "Which firewall evasion scanning technique uses a zombie system with low network activity and fragment identification numbers?",
  options: [
    "Decoy scanning",
    "Idle scanning",
    "Packet fragmentation scanning",
    "Spoof source address scanning"
  ],
  correctAnswer: 1 // Idle scanning
},

{
  question: "Ethical Hacker Jane Smith is performing an SQL injection attack. She wants to test response times to determine true or false conditions and use a second command to verify if the database returns true or false results for user IDs. Which two SQL injection types would help her achieve this?",
  options: [
    "Out-of-band and boolean-based",
    "Time-based and union-based",
    "Time-based and boolean-based",
    "Union-based and error-based"
  ],
  correctAnswer: 2 // Time-based and boolean-based
}
  
];

// Quiz State Variables
// Quiz State Variables
let currentQuestionIndex = 0;
let score = 0;
let timeLeft = 1800; // 30 minutes in seconds
let userAnswers = [];
let timerInterval;
let warningGiven = false;

// DOM Elements
const questionElement = document.getElementById('question');
const optionsContainer = document.getElementById('options-container');
const nextButton = document.getElementById('next-btn');
const resultElement = document.getElementById('result');
const scoreElement = document.getElementById('score');
const progressElement = document.getElementById('progress');
const timerElement = document.getElementById('timer');

// Initialize the Quiz
function initQuiz() {
    currentQuestionIndex = 0;
    score = 0;
    userAnswers = [];
    timeLeft = 1800;
    warningGiven = false;
    nextButton.textContent = "Next";
    nextButton.style.display = "none";
    scoreElement.textContent = `Score: ${score}/${questions.length}`;
    resetTimerStyle();
    startTimer();
    showQuestion();
}

// Timer Functions
function startTimer() {
    clearInterval(timerInterval);
    updateTimerDisplay();
    timerInterval = setInterval(() => {
        timeLeft--;
        updateTimerDisplay();
        
        if (timeLeft <= 120 && !warningGiven) {
            showTimeWarning();
            warningGiven = true;
        }
        
        if (timeLeft <= 0) {
            clearInterval(timerInterval);
            timeUp();
        }
    }, 1000);
}

function updateTimerDisplay() {
    const minutes = Math.floor(timeLeft / 60);
    const seconds = timeLeft % 60;
    timerElement.textContent = `${minutes}:${seconds < 10 ? '0' : ''}${seconds}`;
    
    if (timeLeft <= 120) {
        timerElement.classList.add('warning-active');
    }
}

function showTimeWarning() {
    timerElement.classList.add('warning-flash');
    
    const warningElement = document.createElement('div');
    warningElement.className = 'time-warning';
    warningElement.textContent = 'Only 2 minutes remaining!';
    document.body.appendChild(warningElement);
    
    setTimeout(() => {
        warningElement.remove();
    }, 3000);
}

function resetTimerStyle() {
    timerElement.classList.remove('warning-active', 'warning-flash');
}

function timeUp() {
    clearInterval(timerInterval);
    resetState();
    questionElement.textContent = "Time's Up!";
    optionsContainer.innerHTML = "<p>The quiz has ended because time has run out.</p>";
    showResults();
}

// Quiz Functions
function showQuestion() {
    resetState();
    const currentQuestion = questions[currentQuestionIndex];
    const questionNumber = currentQuestionIndex + 1;
    
    questionElement.textContent = `${questionNumber}. ${currentQuestion.question}`;
    progressElement.textContent = `Question ${questionNumber} of ${questions.length}`;
    
    currentQuestion.options.forEach((option, index) => {
        const button = document.createElement('button');
        button.textContent = option;
        button.classList.add('option-btn');
        button.dataset.index = index;
        button.addEventListener('click', () => selectOption(index));
        optionsContainer.appendChild(button);
    });
}

function resetState() {
    while (optionsContainer.firstChild) {
        optionsContainer.removeChild(optionsContainer.firstChild);
    }
    resultElement.textContent = "";
    resultElement.className = "";
}

function selectOption(selectedIndex) {
    const currentQuestion = questions[currentQuestionIndex];
    userAnswers[currentQuestionIndex] = selectedIndex;
    
    const isCorrect = selectedIndex === currentQuestion.correctAnswer;
    if (isCorrect) {
        score++;
        resultElement.textContent = "Correct!";
        resultElement.classList.add("correct");
    } else {
        resultElement.textContent = `Incorrect! The correct answer was: ${currentQuestion.options[currentQuestion.correctAnswer]}`;
        resultElement.classList.add("incorrect");
    }
    
    const optionButtons = optionsContainer.querySelectorAll('.option-btn');
    optionButtons.forEach(button => {
        button.disabled = true;
        if (parseInt(button.dataset.index) === currentQuestion.correctAnswer) {
            button.classList.add("correct-answer");
        }
    });
    
    scoreElement.textContent = `Score: ${score}/${questions.length}`;
    nextButton.style.display = "block";
}

function handleNextButton() {
    currentQuestionIndex++;
    if (currentQuestionIndex < questions.length) {
        showQuestion();
        nextButton.style.display = "none";
    } else {
        clearInterval(timerInterval);
        showResults();
    }
}

function showResults() {
    resetState();
    questionElement.textContent = "Quiz Completed!";
    progressElement.textContent = "";
    
    const percentage = Math.round((score / questions.length) * 100);
    resultElement.innerHTML = `
        <h3>Your Score: ${score}/${questions.length} (${percentage}%)</h3>
        <p>Time Remaining: ${Math.floor(timeLeft / 60)}:${timeLeft % 60 < 10 ? '0' : ''}${timeLeft % 60}</p>
        <button id="review-btn" class="review-btn">Review Answers</button>
    `;
    
    nextButton.textContent = "Restart Quiz";
    nextButton.style.display = "block";
    
    document.getElementById('review-btn')?.addEventListener('click', reviewAnswers);
}

function reviewAnswers() {
    resetState();
    questionElement.textContent = "Review Your Answers";
    
    let reviewHTML = "";
    questions.forEach((question, index) => {
        const userAnswer = userAnswers[index];
        const isCorrect = userAnswer === question.correctAnswer;
        
        reviewHTML += `
            <div class="review-item ${isCorrect ? 'correct' : 'incorrect'}">
                <p><strong>Question ${index + 1}:</strong> ${question.question}</p>
                <p><strong>Your answer:</strong> ${question.options[userAnswer] || 'Not answered'}</p>
                ${!isCorrect ? `<p><strong>Correct answer:</strong> ${question.options[question.correctAnswer]}</p>` : ''}
            </div>
        `;
    });
    
    optionsContainer.innerHTML = reviewHTML;
    nextButton.style.display = "block";
}

// Event Listeners
nextButton.addEventListener('click', () => {
    if (currentQuestionIndex < questions.length) {
        handleNextButton();
    } else {
        initQuiz();
    }
});

// Start the quiz when the page loads
window.onload = initQuiz;