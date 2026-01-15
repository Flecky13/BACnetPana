namespace bacneTPana.Models
{
    /// <summary>
    /// Informationen zu unterstützten Netzwerkprotokollen
    /// </summary>
    public class ProtocolInfo
    {
        public string? Name { get; set; }
        public string? Abbreviation { get; set; }
        public int Layer { get; set; } // 2, 3, 4, 7 (OSI-Modell)
        public string? Description { get; set; }
        public List<int> CommonPorts { get; set; }

        public ProtocolInfo()
        {
            CommonPorts = new List<int>();
        }

        public static Dictionary<string, ProtocolInfo> GetDefaultProtocols()
        {
            return new Dictionary<string, ProtocolInfo>
            {
                // Layer 2 Protokolle
                { "Arp", new ProtocolInfo { Name = "ARP", Abbreviation = "ARP", Layer = 2, Description = "Address Resolution Protocol" } },

                // Layer 3 Protokolle
                { "IPv4", new ProtocolInfo { Name = "IPv4", Abbreviation = "IPv4", Layer = 3, Description = "Internet Protocol v4" } },
                { "IPv6", new ProtocolInfo { Name = "IPv6", Abbreviation = "IPv6", Layer = 3, Description = "Internet Protocol v6" } },
                { "ICMP", new ProtocolInfo { Name = "ICMP", Abbreviation = "ICMP", Layer = 3, Description = "Internet Control Message Protocol" } },
                { "IGMP", new ProtocolInfo { Name = "IGMP", Abbreviation = "IGMP", Layer = 3, Description = "Internet Group Management Protocol" } },

                // Layer 4 Protokolle
                { "TCP", new ProtocolInfo { Name = "TCP", Abbreviation = "TCP", Layer = 4, Description = "Transmission Control Protocol" } },
                { "UDP", new ProtocolInfo { Name = "UDP", Abbreviation = "UDP", Layer = 4, Description = "User Datagram Protocol" } },

                // Layer 7 Protokolle - Well-Known Ports (0-1023)
                { "FTP-DATA", new ProtocolInfo { Name = "FTP Data", Abbreviation = "FTP-DATA", Layer = 7, Description = "File Transfer Protocol (Data)", CommonPorts = new List<int> { 20 } } },
                { "FTP", new ProtocolInfo { Name = "FTP", Abbreviation = "FTP", Layer = 7, Description = "File Transfer Protocol (Control)", CommonPorts = new List<int> { 21 } } },
                { "SSH", new ProtocolInfo { Name = "SSH", Abbreviation = "SSH", Layer = 7, Description = "Secure Shell", CommonPorts = new List<int> { 22 } } },
                { "TELNET", new ProtocolInfo { Name = "Telnet", Abbreviation = "TELNET", Layer = 7, Description = "Telnet Protocol", CommonPorts = new List<int> { 23 } } },
                { "SMTP", new ProtocolInfo { Name = "SMTP", Abbreviation = "SMTP", Layer = 7, Description = "Simple Mail Transfer Protocol", CommonPorts = new List<int> { 25, 587, 465 } } },
                { "DNS", new ProtocolInfo { Name = "DNS", Abbreviation = "DNS", Layer = 7, Description = "Domain Name System", CommonPorts = new List<int> { 53 } } },
                { "DHCP", new ProtocolInfo { Name = "DHCP", Abbreviation = "DHCP", Layer = 7, Description = "Dynamic Host Configuration Protocol", CommonPorts = new List<int> { 67, 68 } } },
                { "TFTP", new ProtocolInfo { Name = "TFTP", Abbreviation = "TFTP", Layer = 7, Description = "Trivial File Transfer Protocol", CommonPorts = new List<int> { 69 } } },
                { "HTTP", new ProtocolInfo { Name = "HTTP", Abbreviation = "HTTP", Layer = 7, Description = "Hypertext Transfer Protocol", CommonPorts = new List<int> { 80, 8000, 8080, 8888 } } },
                { "KERBEROS", new ProtocolInfo { Name = "Kerberos", Abbreviation = "KERBEROS", Layer = 7, Description = "Kerberos Authentication", CommonPorts = new List<int> { 88 } } },
                { "POP3", new ProtocolInfo { Name = "POP3", Abbreviation = "POP3", Layer = 7, Description = "Post Office Protocol 3", CommonPorts = new List<int> { 110, 995 } } },
                { "NTP", new ProtocolInfo { Name = "NTP", Abbreviation = "NTP", Layer = 7, Description = "Network Time Protocol", CommonPorts = new List<int> { 123 } } },
                { "NETBIOS-NS", new ProtocolInfo { Name = "NetBIOS Name Service", Abbreviation = "NETBIOS-NS", Layer = 7, Description = "NetBIOS Name Service", CommonPorts = new List<int> { 137 } } },
                { "NETBIOS-DGM", new ProtocolInfo { Name = "NetBIOS Datagram", Abbreviation = "NETBIOS-DGM", Layer = 7, Description = "NetBIOS Datagram Service", CommonPorts = new List<int> { 138 } } },
                { "NETBIOS-SSN", new ProtocolInfo { Name = "NetBIOS Session", Abbreviation = "NETBIOS-SSN", Layer = 7, Description = "NetBIOS Session Service", CommonPorts = new List<int> { 139 } } },
                { "IMAP", new ProtocolInfo { Name = "IMAP", Abbreviation = "IMAP", Layer = 7, Description = "Internet Message Access Protocol", CommonPorts = new List<int> { 143, 993 } } },
                { "SNMP", new ProtocolInfo { Name = "SNMP", Abbreviation = "SNMP", Layer = 7, Description = "Simple Network Management Protocol", CommonPorts = new List<int> { 161, 162 } } },
                { "BGP", new ProtocolInfo { Name = "BGP", Abbreviation = "BGP", Layer = 7, Description = "Border Gateway Protocol", CommonPorts = new List<int> { 179 } } },
                { "LDAP", new ProtocolInfo { Name = "LDAP", Abbreviation = "LDAP", Layer = 7, Description = "Lightweight Directory Access Protocol", CommonPorts = new List<int> { 389, 636 } } },
                { "HTTPS", new ProtocolInfo { Name = "HTTPS", Abbreviation = "HTTPS", Layer = 7, Description = "HTTP Secure", CommonPorts = new List<int> { 443, 8443 } } },
                { "SMB", new ProtocolInfo { Name = "SMB", Abbreviation = "SMB", Layer = 7, Description = "Server Message Block", CommonPorts = new List<int> { 445 } } },
                { "SMTPS", new ProtocolInfo { Name = "SMTPS", Abbreviation = "SMTPS", Layer = 7, Description = "SMTP over SSL", CommonPorts = new List<int> { 465 } } },
                { "SYSLOG", new ProtocolInfo { Name = "Syslog", Abbreviation = "SYSLOG", Layer = 7, Description = "Syslog Protocol", CommonPorts = new List<int> { 514 } } },
                { "RTSP", new ProtocolInfo { Name = "RTSP", Abbreviation = "RTSP", Layer = 7, Description = "Real Time Streaming Protocol", CommonPorts = new List<int> { 554 } } },
                { "LDAPS", new ProtocolInfo { Name = "LDAPS", Abbreviation = "LDAPS", Layer = 7, Description = "LDAP over SSL", CommonPorts = new List<int> { 636 } } },
                { "IMAPS", new ProtocolInfo { Name = "IMAPS", Abbreviation = "IMAPS", Layer = 7, Description = "IMAP over SSL", CommonPorts = new List<int> { 993 } } },
                { "POP3S", new ProtocolInfo { Name = "POP3S", Abbreviation = "POP3S", Layer = 7, Description = "POP3 over SSL", CommonPorts = new List<int> { 995 } } },

                // Layer 7 Protokolle - Registered Ports (1024-49151)
                { "SOCKS", new ProtocolInfo { Name = "SOCKS", Abbreviation = "SOCKS", Layer = 7, Description = "SOCKS Proxy Protocol", CommonPorts = new List<int> { 1080 } } },
                { "MSSQL", new ProtocolInfo { Name = "MS SQL Server", Abbreviation = "MSSQL", Layer = 7, Description = "Microsoft SQL Server", CommonPorts = new List<int> { 1433, 1434 } } },
                { "ORACLE", new ProtocolInfo { Name = "Oracle DB", Abbreviation = "ORACLE", Layer = 7, Description = "Oracle Database", CommonPorts = new List<int> { 1521, 1522 } } },
                { "NFS", new ProtocolInfo { Name = "NFS", Abbreviation = "NFS", Layer = 7, Description = "Network File System", CommonPorts = new List<int> { 2049 } } },
                { "MYSQL", new ProtocolInfo { Name = "MySQL", Abbreviation = "MYSQL", Layer = 7, Description = "MySQL Database", CommonPorts = new List<int> { 3306 } } },
                { "RDP", new ProtocolInfo { Name = "RDP", Abbreviation = "RDP", Layer = 7, Description = "Remote Desktop Protocol", CommonPorts = new List<int> { 3389 } } },
                { "RDPUDP", new ProtocolInfo { Name = "RDP over UDP", Abbreviation = "RDPUDP", Layer = 7, Description = "Remote Desktop Protocol UDP", CommonPorts = new List<int> { 3389 } } },
                { "SIP", new ProtocolInfo { Name = "SIP", Abbreviation = "SIP", Layer = 7, Description = "Session Initiation Protocol", CommonPorts = new List<int> { 5060, 5061 } } },
                { "POSTGRESQL", new ProtocolInfo { Name = "PostgreSQL", Abbreviation = "POSTGRESQL", Layer = 7, Description = "PostgreSQL Database", CommonPorts = new List<int> { 5432 } } },
                { "VNC", new ProtocolInfo { Name = "VNC", Abbreviation = "VNC", Layer = 7, Description = "Virtual Network Computing", CommonPorts = new List<int> { 5900, 5901, 5902, 5903 } } },
                { "X11", new ProtocolInfo { Name = "X11", Abbreviation = "X11", Layer = 7, Description = "X Window System", CommonPorts = new List<int> { 6000, 6001, 6002, 6003 } } },
                { "REDIS", new ProtocolInfo { Name = "Redis", Abbreviation = "REDIS", Layer = 7, Description = "Redis Database", CommonPorts = new List<int> { 6379 } } },
                { "CASSANDRA", new ProtocolInfo { Name = "Cassandra", Abbreviation = "CASSANDRA", Layer = 7, Description = "Apache Cassandra", CommonPorts = new List<int> { 9042, 9160 } } },
                { "ELASTICSEARCH", new ProtocolInfo { Name = "Elasticsearch", Abbreviation = "ELASTICSEARCH", Layer = 7, Description = "Elasticsearch", CommonPorts = new List<int> { 9200, 9300 } } },
                { "MEMCACHED", new ProtocolInfo { Name = "Memcached", Abbreviation = "MEMCACHED", Layer = 7, Description = "Memcached", CommonPorts = new List<int> { 11211 } } },
                { "MONGODB", new ProtocolInfo { Name = "MongoDB", Abbreviation = "MONGODB", Layer = 7, Description = "MongoDB Database", CommonPorts = new List<int> { 27017, 27018, 27019 } } },
                { "BACnet", new ProtocolInfo { Name = "BACnet", Abbreviation = "BACnet", Layer = 7, Description = "Building Automation and Control Networks", CommonPorts = Enumerable.Range(47808, 16).ToList() } },
            };
        }

        /// <summary>
        /// Erkennt das Application-Layer-Protokoll basierend auf Port und Payload
        /// </summary>
        public static string? DetectApplicationProtocol(string transportProtocol, int sourcePort, int destinationPort, byte[]? payload)
        {
            var protocols = GetDefaultProtocols();

            // Prüfe bekannte Ports
            foreach (var protocol in protocols.Values.Where(p => p.Layer == 7))
            {
                if (protocol.CommonPorts.Contains(sourcePort) || protocol.CommonPorts.Contains(destinationPort))
                {
                    return protocol.Abbreviation;
                }
            }

            // BACnet spezielle Erkennung (UDP Port 47808-47823)
            if (transportProtocol == "Udp" &&
                ((sourcePort >= 47808 && sourcePort <= 47823) ||
                 (destinationPort >= 47808 && destinationPort <= 47823)))
            {
                return "BACnet";
            }

            // HTTP-Erkennung anhand Payload
            if (payload != null && payload.Length > 4 && transportProtocol == "Tcp")
            {
                var text = System.Text.Encoding.ASCII.GetString(payload.Take(Math.Min(100, payload.Length)).ToArray());
                if (text.StartsWith("GET ") || text.StartsWith("POST ") || text.StartsWith("HTTP/"))
                {
                    return "HTTP";
                }
            }

            return null;
        }
    }
}
