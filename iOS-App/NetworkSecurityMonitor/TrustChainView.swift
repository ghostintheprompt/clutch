//
//  TrustChainView.swift
//  NetworkSecurityMonitor (iOS only)
//
//  Cryptographic Trust Chain Visualization + SIGINT Tower Map

#if os(iOS)
//
//  TrustChainView  — inspects TLS certificate chain and DNSSEC posture for a
//                    probe endpoint, showing each link in the chain with validity
//                    status, expiry, and key algorithm.
//
//  SIGINTMapView   — plots observed cellular towers on a MapKit map, color-coding
//                    by threat level and flagging Stingray-signature towers with
//                    a distinct indicator.
//

import SwiftUI
import MapKit
import Network
import CryptoKit

// MARK: - Data Models

struct CertificateInfo: Identifiable {
    let id = UUID()
    let subject: String
    let issuer: String
    let notBefore: Date
    let notAfter: Date
    let keyAlgorithm: String
    let serialNumber: String
    let isCA: Bool
    var isTrusted: Bool = false
    var isExpired: Bool { notAfter < Date() }
    var isExpiringSoon: Bool { notAfter < Date().addingTimeInterval(30 * 24 * 3600) }
    var validityPercent: Double {
        let total = notAfter.timeIntervalSince(notBefore)
        let elapsed = Date().timeIntervalSince(notBefore)
        return max(0, min(1, elapsed / total))
    }
}

struct DNSSECStatus {
    enum State: String {
        case validated   = "VALIDATED"
        case unsigned    = "UNSIGNED"
        case bogus       = "BOGUS"
        case indeterminate = "INDETERMINATE"
        case unavailable = "UNAVAILABLE"
    }
    let state: State
    let domain: String
    let checkTimestamp: Date
    var stateColor: Color {
        switch state {
        case .validated:    return .green
        case .unsigned:     return .yellow
        case .bogus:        return .red
        case .indeterminate, .unavailable: return .gray
        }
    }
}

struct TowerAnnotation: Identifiable {
    let id: String
    let coordinate: CLLocationCoordinate2D
    let technology: String
    let signalStrength: Int
    let mcc: String
    let mnc: String
    let threatLevel: ThreatLevel
    let isStingrayCandidate: Bool
    let detectedAt: Date

    enum ThreatLevel: String, CaseIterable {
        case clean    = "CLEAN"
        case suspect  = "SUSPECT"
        case confirmed = "CONFIRMED"
    }

    var annotationColor: Color {
        switch threatLevel {
        case .clean:     return .green
        case .suspect:   return .orange
        case .confirmed: return .red
        }
    }
}

// MARK: - TLS Probe Service

@MainActor
class TLSProbeService: NSObject, ObservableObject {
    @Published var certificates: [CertificateInfo] = []
    @Published var dnssec: DNSSECStatus?
    @Published var isProbing = false
    @Published var lastError: String?
    @Published var probeTarget: String = "www.google.com"
    @Published var connectionProtocol: String = "Unknown"
    @Published var cipherSuite: String = "Unknown"

    private var probeTask: Task<Void, Never>?

    func startProbe(host: String) {
        probeTask?.cancel()
        isProbing = true
        lastError = nil
        certificates = []
        dnssec = nil
        probeTarget = host

        probeTask = Task { [weak self] in
            await self?.performTLSProbe(host: host)
            await self?.performDNSSECCheck(domain: host)
        }
    }

    private func performTLSProbe(host: String) async {
        // Use NWConnection with TLS to inspect certificate chain
        let params = NWParameters.tls
        let tlsOpts = params.defaultProtocolStack.applicationProtocols.first as? NWProtocolTLS.Options
            ?? NWProtocolTLS.Options()

        // Install a verify block to capture the trust object
        sec_protocol_options_set_verify_block(tlsOpts.securityProtocolOptions, { [weak self] metadata, trust, verifyComplete in
            Task { @MainActor [weak self] in
                self?.extractCertificates(from: trust)
                self?.extractConnectionMeta(from: metadata)
            }
            verifyComplete(true) // allow connection even if we inspect
        }, DispatchQueue.global())

        let endpoint = NWEndpoint.hostPort(host: NWEndpoint.Host(host), port: .https)
        let connection = NWConnection(to: endpoint, using: params)

        return await withCheckedContinuation { continuation in
            connection.stateUpdateHandler = { [weak self] state in
                Task { @MainActor [weak self] in
                    switch state {
                    case .ready:
                        self?.isProbing = false
                        connection.cancel()
                        continuation.resume()
                    case .failed(let err):
                        self?.lastError = err.localizedDescription
                        self?.isProbing = false
                        continuation.resume()
                    case .cancelled:
                        self?.isProbing = false
                        continuation.resume()
                    default: break
                    }
                }
            }
            connection.start(queue: .global())

            // Timeout after 10 seconds
            Task {
                try? await Task.sleep(nanoseconds: 10_000_000_000)
                connection.cancel()
                continuation.resume()
            }
        }
    }

    private func extractCertificates(from trustRef: sec_trust_t) {
        let trust: SecTrust = sec_trust_copy_ref(trustRef).takeRetainedValue()

        var certs: [CertificateInfo] = []
        let count = SecTrustGetCertificateCount(trust)

        for i in 0..<count {
            guard let cert = SecTrustGetCertificateAtIndex(trust, i) else { continue }
            let info = parseCertificate(cert, index: i, trust: trust)
            certs.append(info)
        }

        self.certificates = certs
    }

    private func parseCertificate(_ cert: SecCertificate, index: Int, trust: SecTrust) -> CertificateInfo {
        let subject = SecCertificateCopySubjectSummary(cert) as String? ?? "Unknown Subject"

        // Extract issuer via certificate values
        var issuer = "Unknown Issuer"
        var notBefore = Date.distantPast
        var notAfter = Date.distantFuture
        var keyAlgorithm = "Unknown"
        var serial = "Unknown"
        var isCA = index > 0

        if let values = SecCertificateCopyValues(cert, nil, nil) as? [String: Any] {
            // Issuer
            if let issuerDict = values[kSecOIDX509V1IssuerName as String] as? [String: Any],
               let issuerVal = issuerDict[kSecPropertyKeyValue as String] as? [[String: Any]] {
                issuer = issuerVal.first?[kSecPropertyKeyValue as String] as? String ?? issuer
            }

            // Validity dates
            if let nbDict = values[kSecOIDX509V1ValidityNotBefore as String] as? [String: Any],
               let nb = nbDict[kSecPropertyKeyValue as String] as? NSNumber {
                notBefore = Date(timeIntervalSinceReferenceDate: nb.doubleValue)
            }
            if let naDict = values[kSecOIDX509V1ValidityNotAfter as String] as? [String: Any],
               let na = naDict[kSecPropertyKeyValue as String] as? NSNumber {
                notAfter = Date(timeIntervalSinceReferenceDate: na.doubleValue)
            }

            // Key algorithm
            if let keyDict = values[kSecOIDX509V1SubjectPublicKeyAlgorithm as String] as? [String: Any],
               let algo = keyDict[kSecPropertyKeyValue as String] as? String {
                keyAlgorithm = algo
            }

            // Serial
            if let snDict = values[kSecOIDX509V1SerialNumber as String] as? [String: Any],
               let sn = snDict[kSecPropertyKeyValue as String] as? Data {
                serial = sn.map { String(format: "%02X", $0) }.joined(separator: ":")
            }
        }

        var isTrusted = false
        var trustResult: SecTrustResultType = .invalid
        SecTrustGetTrustResult(trust, &trustResult)
        isTrusted = (trustResult == .proceed || trustResult == .unspecified)

        return CertificateInfo(
            subject: subject,
            issuer: issuer,
            notBefore: notBefore,
            notAfter: notAfter,
            keyAlgorithm: keyAlgorithm,
            serialNumber: serial,
            isCA: isCA,
            isTrusted: isTrusted && index == 0
        )
    }

    private func extractConnectionMeta(from metadata: sec_protocol_metadata_t) {
        // TLS version
        let version = sec_protocol_metadata_get_negotiated_tls_protocol_version(metadata)
        switch version {
        case .TLSv13: connectionProtocol = "TLS 1.3"
        case .TLSv12: connectionProtocol = "TLS 1.2"
        default:      connectionProtocol = "TLS (unknown version)"
        }

        // Cipher suite
        let cipher = sec_protocol_metadata_get_negotiated_tls_ciphersuite(metadata)
        cipherSuite = cipherSuiteName(cipher)
    }

    private func cipherSuiteName(_ cs: tls_ciphersuite_t) -> String {
        switch cs {
        case .AES_256_GCM_SHA384:    return "AES-256-GCM-SHA384"
        case .AES_128_GCM_SHA256:    return "AES-128-GCM-SHA256"
        case .CHACHA20_POLY1305_SHA256: return "ChaCha20-Poly1305"
        case .ECDHE_RSA_WITH_AES_256_GCM_SHA384: return "ECDHE-RSA-AES256-GCM-SHA384"
        default: return "0x\(String(cs.rawValue, radix: 16, uppercase: true))"
        }
    }

    // DNSSEC verification is not directly available through public iOS APIs.
    // We probe by querying the DNS resolver and checking for the AD (Authenticated Data)
    // bit in the response, which indicates DNSSEC validation by the resolver.
    private func performDNSSECCheck(domain: String) async {
        // Best-effort: send a raw DNS query with DNSSEC OK (DO) bit set,
        // check if the AD flag is set in the response.
        guard let socketFD = createUDPSocket() else {
            dnssec = DNSSECStatus(state: .unavailable, domain: domain, checkTimestamp: Date())
            return
        }
        defer { close(socketFD) }

        let query = buildDNSSECQuery(domain: domain)
        let resolverIP = "8.8.8.8"
        var resolverAddr = sockaddr_in()
        resolverAddr.sin_family = sa_family_t(AF_INET)
        resolverAddr.sin_port = CFSwapInt16HostToBig(53)
        inet_pton(AF_INET, resolverIP, &resolverAddr.sin_addr)

        let sent = withUnsafeBytes(of: &resolverAddr) { addrPtr in
            query.withUnsafeBytes { queryPtr in
                sendto(socketFD, queryPtr.baseAddress, query.count, 0,
                       addrPtr.baseAddress?.assumingMemoryBound(to: sockaddr.self),
                       socklen_t(MemoryLayout<sockaddr_in>.size))
            }
        }

        guard sent > 0 else {
            dnssec = DNSSECStatus(state: .unavailable, domain: domain, checkTimestamp: Date())
            return
        }

        var response = Data(count: 512)
        let received = response.withUnsafeMutableBytes { ptr in
            recv(socketFD, ptr.baseAddress, 512, 0)
        }

        guard received > 3 else {
            dnssec = DNSSECStatus(state: .unavailable, domain: domain, checkTimestamp: Date())
            return
        }

        response = response.prefix(received)
        // DNS flags are bytes 2-3; AD bit is bit 5 of byte 3 (0x0020)
        let flags = UInt16(response[2]) << 8 | UInt16(response[3])
        let adBit = (flags & 0x0020) != 0
        // RCODE is low 4 bits of flags byte 3
        let rcode = flags & 0x000F

        let state: DNSSECStatus.State
        if rcode == 2 { // SERVFAIL with DNSSEC often means bogus
            state = .bogus
        } else if adBit {
            state = .validated
        } else {
            state = .unsigned
        }

        dnssec = DNSSECStatus(state: state, domain: domain, checkTimestamp: Date())
    }

    private func createUDPSocket() -> Int32? {
        let fd = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP)
        guard fd >= 0 else { return nil }
        var timeout = timeval(tv_sec: 3, tv_usec: 0)
        setsockopt(fd, SOL_SOCKET, SO_RCVTIMEO, &timeout, socklen_t(MemoryLayout<timeval>.size))
        return fd
    }

    private func buildDNSSECQuery(domain: String) -> Data {
        // DNS query with EDNS0 OPT record and DO bit to request DNSSEC records
        var packet = Data()
        // Transaction ID
        packet.append(contentsOf: [0x12, 0x34])
        // Flags: recursive desired
        packet.append(contentsOf: [0x01, 0x00])
        // Counts: 1 question, 0 answer, 0 authority, 1 additional (OPT)
        packet.append(contentsOf: [0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01])

        // QNAME
        for label in domain.split(separator: ".") {
            let bytes = Array(label.utf8)
            packet.append(UInt8(bytes.count))
            packet.append(contentsOf: bytes)
        }
        packet.append(0x00)
        // QTYPE A, QCLASS IN
        packet.append(contentsOf: [0x00, 0x01, 0x00, 0x01])

        // OPT pseudo-RR with DO bit (DNSSEC OK)
        packet.append(0x00)                        // root name
        packet.append(contentsOf: [0x00, 0x29])    // TYPE OPT
        packet.append(contentsOf: [0x10, 0x00])    // UDP payload size 4096
        packet.append(contentsOf: [0x00, 0x00, 0x00, 0x00]) // extended RCODE + version
        packet.append(contentsOf: [0x80, 0x00])    // Z flags: DO bit set
        packet.append(contentsOf: [0x00, 0x00])    // RDLENGTH = 0

        return packet
    }
}

// MARK: - TrustChainView

struct TrustChainView: View {
    @StateObject private var probeService = TLSProbeService()
    @State private var hostInput = "www.google.com"

    var body: some View {
        NavigationStack {
            ScrollView {
                VStack(spacing: 20) {
                    probeInputSection
                    if probeService.isProbing {
                        ProgressView("Probing TLS connection…")
                            .padding()
                    }
                    if let err = probeService.lastError {
                        errorBanner(err)
                    }
                    if !probeService.certificates.isEmpty {
                        connectionMetaSection
                        dnssecSection
                        certificateChainSection
                    }
                }
                .padding()
            }
            .navigationTitle("Trust Chain")
            .navigationBarTitleDisplayMode(.inline)
            .background(Color.black)
            .colorScheme(.dark)
        }
    }

    private var probeInputSection: some View {
        VStack(spacing: 12) {
            Text("TLS / DNSSEC Inspector")
                .font(.headline)
                .foregroundColor(.white)

            HStack {
                Image(systemName: "lock.shield")
                    .foregroundColor(.cyan)
                TextField("Host (e.g. google.com)", text: $hostInput)
                    .textFieldStyle(.roundedBorder)
                    .textInputAutocapitalization(.never)
                    .disableAutocorrection(true)
                    .keyboardType(.URL)
            }
            .padding()
            .background(Color(white: 0.12))
            .cornerRadius(12)

            Button(action: { probeService.startProbe(host: hostInput) }) {
                Label("Inspect Connection", systemImage: "shield.lefthalf.filled")
                    .frame(maxWidth: .infinity)
                    .padding(.vertical, 12)
                    .background(Color.cyan)
                    .foregroundColor(.black)
                    .fontWeight(.semibold)
                    .cornerRadius(10)
            }
            .disabled(probeService.isProbing || hostInput.isEmpty)
        }
    }

    private var connectionMetaSection: some View {
        GroupBox {
            HStack {
                metaChip(label: "Protocol", value: probeService.connectionProtocol,
                         color: probeService.connectionProtocol.contains("1.3") ? .green : .orange)
                Spacer()
                metaChip(label: "Cipher", value: probeService.cipherSuite, color: .cyan)
            }
        } label: {
            Label("Connection", systemImage: "network.badge.shield.half.filled")
                .foregroundColor(.white)
        }
        .groupBoxStyle(DarkGroupBoxStyle())
    }

    private func metaChip(label: String, value: String, color: Color) -> some View {
        VStack(alignment: .leading, spacing: 4) {
            Text(label).font(.caption).foregroundColor(.gray)
            Text(value).font(.caption).fontWeight(.semibold).foregroundColor(color)
        }
    }

    private var dnssecSection: some View {
        Group {
            if let dns = probeService.dnssec {
                GroupBox {
                    HStack {
                        Circle()
                            .fill(dns.stateColor)
                            .frame(width: 10, height: 10)
                        Text(dns.state.rawValue)
                            .foregroundColor(dns.stateColor)
                            .fontWeight(.semibold)
                        Spacer()
                        Text(dns.domain)
                            .font(.caption)
                            .foregroundColor(.gray)
                    }
                    if dns.state == .unsigned {
                        Text("Domain does not publish DNSSEC records. DNS responses are unauthenticated and susceptible to injection.")
                            .font(.caption2)
                            .foregroundColor(.yellow)
                            .padding(.top, 4)
                    } else if dns.state == .bogus {
                        Text("DNSSEC validation FAILED — resolver received invalid signatures. Possible DNS poisoning in progress.")
                            .font(.caption2)
                            .foregroundColor(.red)
                            .padding(.top, 4)
                    }
                } label: {
                    Label("DNSSEC", systemImage: "checkmark.shield")
                        .foregroundColor(.white)
                }
                .groupBoxStyle(DarkGroupBoxStyle())
            }
        }
    }

    private var certificateChainSection: some View {
        VStack(alignment: .leading, spacing: 12) {
            Text("Certificate Chain")
                .font(.headline)
                .foregroundColor(.white)

            ForEach(Array(probeService.certificates.enumerated()), id: \.element.id) { idx, cert in
                CertificateCard(cert: cert, chainIndex: idx,
                                totalInChain: probeService.certificates.count)
            }
        }
    }

    private func errorBanner(_ message: String) -> some View {
        HStack {
            Image(systemName: "exclamationmark.triangle.fill").foregroundColor(.red)
            Text(message).font(.caption).foregroundColor(.red)
            Spacer()
        }
        .padding()
        .background(Color.red.opacity(0.15))
        .cornerRadius(8)
    }
}

struct CertificateCard: View {
    let cert: CertificateInfo
    let chainIndex: Int
    let totalInChain: Int
    @State private var expanded = false

    var body: some View {
        VStack(alignment: .leading, spacing: 0) {
            // Header row
            Button(action: { withAnimation(.easeInOut(duration: 0.2)) { expanded.toggle() } }) {
                HStack(spacing: 12) {
                    chainIcon
                    VStack(alignment: .leading, spacing: 2) {
                        Text(cert.subject)
                            .font(.subheadline)
                            .fontWeight(.medium)
                            .foregroundColor(.white)
                            .lineLimit(1)
                        Text(chainIndex == 0 ? "End-entity" : cert.isCA ? "CA" : "Intermediate")
                            .font(.caption2)
                            .foregroundColor(.gray)
                    }
                    Spacer()
                    statusBadge
                    Image(systemName: expanded ? "chevron.up" : "chevron.down")
                        .font(.caption)
                        .foregroundColor(.gray)
                }
                .padding(12)
            }

            // Expanded detail
            if expanded {
                Divider().background(Color.gray.opacity(0.3))
                VStack(alignment: .leading, spacing: 8) {
                    detailRow("Issuer", cert.issuer)
                    detailRow("Algorithm", cert.keyAlgorithm)
                    detailRow("Serial", String(cert.serialNumber.prefix(24)) + "…")
                    detailRow("Not Before", formatDate(cert.notBefore))
                    detailRow("Not After", formatDate(cert.notAfter))

                    // Validity bar
                    VStack(alignment: .leading, spacing: 4) {
                        Text("Validity").font(.caption2).foregroundColor(.gray)
                        GeometryReader { geo in
                            ZStack(alignment: .leading) {
                                RoundedRectangle(cornerRadius: 3)
                                    .fill(Color.gray.opacity(0.3))
                                    .frame(height: 6)
                                RoundedRectangle(cornerRadius: 3)
                                    .fill(validityColor)
                                    .frame(width: geo.size.width * cert.validityPercent, height: 6)
                            }
                        }
                        .frame(height: 6)
                    }
                }
                .padding(.horizontal, 12)
                .padding(.vertical, 10)
            }
        }
        .background(Color(white: 0.1))
        .cornerRadius(10)
        .overlay(
            RoundedRectangle(cornerRadius: 10)
                .stroke(borderColor, lineWidth: 1)
        )
    }

    private var chainIcon: some View {
        ZStack {
            Circle()
                .fill(iconColor.opacity(0.2))
                .frame(width: 32, height: 32)
            Image(systemName: chainIndex == 0 ? "lock.fill" : cert.isCA ? "building.columns.fill" : "link")
                .font(.caption)
                .foregroundColor(iconColor)
        }
    }

    private var statusBadge: some View {
        Group {
            if cert.isExpired {
                badge("EXPIRED", .red)
            } else if cert.isExpiringSoon {
                badge("EXPIRING", .orange)
            } else if cert.isTrusted {
                badge("TRUSTED", .green)
            } else {
                badge("VALID", .cyan)
            }
        }
    }

    private func badge(_ text: String, _ color: Color) -> some View {
        Text(text)
            .font(.system(size: 9, weight: .bold))
            .foregroundColor(color)
            .padding(.horizontal, 6)
            .padding(.vertical, 2)
            .background(color.opacity(0.15))
            .cornerRadius(4)
    }

    private func detailRow(_ label: String, _ value: String) -> some View {
        HStack(alignment: .top) {
            Text(label).font(.caption2).foregroundColor(.gray).frame(width: 70, alignment: .leading)
            Text(value).font(.caption2).foregroundColor(.white).lineLimit(2)
        }
    }

    private func formatDate(_ date: Date) -> String {
        let f = DateFormatter()
        f.dateStyle = .medium
        f.timeStyle = .short
        return f.string(from: date)
    }

    private var iconColor: Color {
        if cert.isExpired { return .red }
        if cert.isExpiringSoon { return .orange }
        return chainIndex == 0 ? .cyan : .gray
    }
    private var borderColor: Color { cert.isExpired ? .red.opacity(0.5) : Color.gray.opacity(0.25) }
    private var validityColor: Color {
        if cert.isExpired { return .red }
        if cert.isExpiringSoon { return .orange }
        return .green
    }
}

// MARK: - SIGINT Map View

struct SIGINTMapView: View {
    @Binding var towers: [TowerAnnotation]
    @State private var region = MKCoordinateRegion(
        center: CLLocationCoordinate2D(latitude: 37.7749, longitude: -122.4194),
        span: MKCoordinateSpan(latitudeDelta: 0.05, longitudeDelta: 0.05)
    )
    @State private var selectedTower: TowerAnnotation?

    var body: some View {
        ZStack(alignment: .bottom) {
            Map(coordinateRegion: $region, annotationItems: towers) { tower in
                MapAnnotation(coordinate: tower.coordinate) {
                    TowerMapPin(tower: tower, isSelected: selectedTower?.id == tower.id)
                        .onTapGesture { selectedTower = tower }
                }
            }
            .ignoresSafeArea()
            .colorScheme(.dark)

            // Legend overlay
            legendBar

            // Tower detail card slides up when selected
            if let tower = selectedTower {
                TowerDetailCard(tower: tower) { selectedTower = nil }
                    .transition(.move(edge: .bottom))
                    .animation(.spring(response: 0.35), value: selectedTower?.id)
            }
        }
        .navigationTitle("SIGINT Map")
        .navigationBarTitleDisplayMode(.inline)
        .onAppear { centerOnTowers() }
    }

    private var legendBar: some View {
        HStack(spacing: 16) {
            legendDot(.green,  "Clean")
            legendDot(.orange, "Suspect")
            legendDot(.red,    "Confirmed")
            Spacer()
            Text("\(towers.count) tower\(towers.count == 1 ? "" : "s")")
                .font(.caption2)
                .foregroundColor(.gray)
        }
        .padding(.horizontal, 16)
        .padding(.vertical, 8)
        .background(.ultraThinMaterial)
        .cornerRadius(10)
        .padding(.horizontal, 16)
        .padding(.bottom, selectedTower == nil ? 24 : 220)
    }

    private func legendDot(_ color: Color, _ label: String) -> some View {
        HStack(spacing: 4) {
            Circle().fill(color).frame(width: 8, height: 8)
            Text(label).font(.caption2).foregroundColor(.white)
        }
    }

    private func centerOnTowers() {
        guard !towers.isEmpty else { return }
        let lats = towers.map(\.coordinate.latitude)
        let lons = towers.map(\.coordinate.longitude)
        let center = CLLocationCoordinate2D(
            latitude: (lats.min()! + lats.max()!) / 2,
            longitude: (lons.min()! + lons.max()!) / 2
        )
        let span = MKCoordinateSpan(
            latitudeDelta: max((lats.max()! - lats.min()!) * 1.5, 0.02),
            longitudeDelta: max((lons.max()! - lons.min()!) * 1.5, 0.02)
        )
        region = MKCoordinateRegion(center: center, span: span)
    }
}

struct TowerMapPin: View {
    let tower: TowerAnnotation
    let isSelected: Bool

    var body: some View {
        ZStack {
            if isSelected {
                Circle()
                    .fill(tower.annotationColor.opacity(0.2))
                    .frame(width: 44, height: 44)
            }
            Image(systemName: tower.isStingrayCandidate ? "antenna.radiowaves.left.and.right.slash" : "antenna.radiowaves.left.and.right")
                .font(.system(size: isSelected ? 22 : 16, weight: .bold))
                .foregroundColor(tower.annotationColor)
                .shadow(color: tower.annotationColor.opacity(0.8), radius: isSelected ? 8 : 4)

            if tower.isStingrayCandidate {
                // Warning triangle badge
                Image(systemName: "exclamationmark.triangle.fill")
                    .font(.system(size: 8))
                    .foregroundColor(.yellow)
                    .offset(x: 8, y: -8)
            }
        }
    }
}

struct TowerDetailCard: View {
    let tower: TowerAnnotation
    let onDismiss: () -> Void

    private let dateFormatter: DateFormatter = {
        let f = DateFormatter()
        f.dateStyle = .short
        f.timeStyle = .medium
        return f
    }()

    var body: some View {
        VStack(alignment: .leading, spacing: 12) {
            HStack {
                Image(systemName: tower.isStingrayCandidate
                      ? "antenna.radiowaves.left.and.right.slash"
                      : "antenna.radiowaves.left.and.right")
                    .foregroundColor(tower.annotationColor)
                Text(tower.isStingrayCandidate ? "STINGRAY CANDIDATE" : "Tower Observation")
                    .font(.subheadline)
                    .fontWeight(.semibold)
                    .foregroundColor(tower.annotationColor)
                Spacer()
                Button(action: onDismiss) {
                    Image(systemName: "xmark.circle.fill")
                        .foregroundColor(.gray)
                }
            }

            Divider().background(Color.gray.opacity(0.4))

            LazyVGrid(columns: [GridItem(.flexible()), GridItem(.flexible())], spacing: 8) {
                detailCell("Technology", tower.technology)
                detailCell("Signal", "\(tower.signalStrength) dBm")
                detailCell("MCC / MNC", "\(tower.mcc) / \(tower.mnc)")
                detailCell("Threat", tower.threatLevel.rawValue)
                detailCell("Cell ID", tower.id)
                detailCell("Detected", dateFormatter.string(from: tower.detectedAt))
            }

            if tower.isStingrayCandidate {
                HStack(spacing: 6) {
                    Image(systemName: "exclamationmark.triangle.fill").foregroundColor(.yellow)
                    Text("This tower exhibits signatures consistent with a cell-site simulator. Avoid sensitive communications. Move location if tactically safe.")
                        .font(.caption)
                        .foregroundColor(.yellow)
                }
                .padding(8)
                .background(Color.yellow.opacity(0.08))
                .cornerRadius(8)
            }
        }
        .padding(16)
        .background(.ultraThickMaterial)
        .colorScheme(.dark)
        .cornerRadius(16)
        .shadow(radius: 16)
        .padding(.horizontal, 16)
        .padding(.bottom, 24)
    }

    private func detailCell(_ label: String, _ value: String) -> some View {
        VStack(alignment: .leading, spacing: 2) {
            Text(label).font(.caption2).foregroundColor(.gray)
            Text(value).font(.caption).fontWeight(.medium).foregroundColor(.white)
        }
        .frame(maxWidth: .infinity, alignment: .leading)
        .padding(8)
        .background(Color.white.opacity(0.05))
        .cornerRadius(6)
    }
}

// MARK: - Shared Style

struct DarkGroupBoxStyle: GroupBoxStyle {
    func makeBody(configuration: Configuration) -> some View {
        VStack(alignment: .leading, spacing: 8) {
            configuration.label
            configuration.content
        }
        .padding(12)
        .background(Color(white: 0.1))
        .cornerRadius(10)
    }
}

#endif // os(iOS)
